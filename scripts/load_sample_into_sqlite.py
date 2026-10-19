"""Load the local normal_mixed capture into a fresh temporary SQLite database."""

from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import Base, bulk_insert_packets, make_engine
from app.models import CaptureSession, CaptureSource, Packet, SessionStatus
from app.parser import parse_pcap


def main() -> None:
    """Stream the sample capture into SQLite and report stored packet totals."""
    project_root = Path(__file__).resolve().parents[1]
    pcap_path = project_root / "samples" / "normal_mixed.pcap"
    if not pcap_path.is_file():
        raise FileNotFoundError(f"Capture not found: {pcap_path}")

    started = perf_counter()
    with TemporaryDirectory(prefix="netscope-sample-import-") as temp_dir:
        database_path = (Path(temp_dir) / "netscope.sqlite3").as_posix()
        engine = make_engine(f"sqlite+pysqlite:///{database_path}")
        try:
            Base.metadata.create_all(engine)
            byte_count = 0

            def counted_packets():
                nonlocal byte_count
                for packet in parse_pcap(pcap_path):
                    byte_count += packet["length"]
                    yield packet

            with Session(engine) as db:
                capture = CaptureSession(
                    name=pcap_path.name,
                    source=CaptureSource.PCAP,
                    status=SessionStatus.PROCESSING,
                )
                db.add(capture)
                db.flush()

                stored_count = bulk_insert_packets(
                    db, capture.id, counted_packets(), batch_size=1000,
                )
                capture.packet_count = stored_count
                capture.byte_count = byte_count
                capture.status = SessionStatus.COMPLETED
                db.commit()

                stored_by_protocol = db.execute(
                    select(Packet.protocol, func.count(Packet.id))
                    .where(Packet.session_id == capture.id)
                    .group_by(Packet.protocol)
                    .order_by(Packet.protocol)
                ).all()
                print(f"Capture: {pcap_path.name}")
                print(f"Packets stored: {capture.packet_count}")
                print("Stored packets per protocol:")
                for protocol, count in stored_by_protocol:
                    print(f"  {protocol}: {count}")
                print(f"Seconds taken: {perf_counter() - started:.3f}")
        finally:
            engine.dispose()


if __name__ == "__main__":
    main()

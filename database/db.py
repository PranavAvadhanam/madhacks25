import asyncio
import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from typing import Dict, Any, List

# Import the Base and the model from our models.py file
from .models import Base, ProcessedPacket

# TODO: The database URL should be centralized in a configuration file
#       (e.g., settings.py or a .env file) instead of being hardcoded.
DATABASE_URL = "sqlite:///./packets.db"

# The SQLAlchemy engine is the starting point for any SQLAlchemy application.
engine = create_engine(
    DATABASE_URL,
    # `connect_args` is needed for SQLite to allow multi-threaded access.
    connect_args={"check_same_thread": False}
)

# A SessionLocal class, which will be used to create individual database sessions.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """
    Initializes the database.

    This function creates all tables defined in the models (i.e., ProcessedPacket)
    in the database connected to by the engine. It should be called once at
    application startup.
    """
    print("Initializing the database...")
    Base.metadata.create_all(bind=engine)
    print("Database initialized.")

def bulk_insert_processed_packets(packets: List[Dict[str, Any]]):
    """
    Inserts a batch of processed packets into the database using a single transaction.
    This is a synchronous, blocking function.

    Args:
        packets: A list of dictionaries, where each dictionary contains the data
                 for a processed packet.
    """
    if not packets:
        return
        
    db_session = SessionLocal()
    try:
        # bulk_insert_mappings is highly efficient for inserting many records
        db_session.bulk_insert_mappings(ProcessedPacket, packets)
        db_session.commit()
    finally:
        db_session.close()

async def bulk_insert_processed_packets_async(packets: List[Dict[str, Any]]):
    """
    Asynchronously inserts a batch of packets by running the blocking
    bulk insert function in a separate thread.
    """
    await asyncio.to_thread(bulk_insert_processed_packets, packets)

def get_all_packets() -> List[ProcessedPacket]:
    """
    Retrieves all processed packets from the database.

    Returns:
        A list of ProcessedPacket ORM objects.
    """
    db_session = SessionLocal()
    try:
        print("Fetching all packets from the database...")
        packets = db_session.query(ProcessedPacket).all()
        return packets
    finally:
        db_session.close()

if __name__ == '__main__':
    # A simple script to initialize the DB and test inserting/reading data.
    init_db()

    # Example of inserting a batch of packets
    test_packets = [
        {
            'source_ip': '192.168.1.100', 'destination_ip': '8.8.8.8',
            'protocol_type': 'DNS', 'summary': 'Query A www.example.com',
            'timestamp': '2025-11-22 13:45:00'
        },
        {
            'source_ip': '192.168.1.101', 'destination_ip': '8.8.4.4',
            'protocol_type': 'ICMP', 'summary': 'Echo Request',
            'timestamp': '2025-11-22 13:45:01'
        }
    ]
    bulk_insert_processed_packets(test_packets)

    # Example of fetching all packets
    all_packets = get_all_packets()
    print(f"Found {len(all_packets)} packets in the database.")
    for packet in all_packets:
        print(packet)

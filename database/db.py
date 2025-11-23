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
    # `connect_args` is passed to the DB-API driver.
    connect_args={
        "check_same_thread": False,
        # Increase the timeout to 20 seconds to wait for the database lock
        # to be released, which is crucial in a multi-threaded writer scenario.
        "timeout": 20
    }
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

def prune_database(limit: int = 10000):
    """
    Checks the number of rows in the database and deletes the oldest entries
    if the count exceeds the specified limit.
    """
    db_session = SessionLocal()
    try:
        row_count = db_session.query(ProcessedPacket).count()
        
        if row_count > limit:
            num_to_delete = row_count - limit
            # Since IDs are auto-incrementing, the lowest IDs are the oldest.
            # We find the ID of the last row we want to delete.
            subquery = db_session.query(ProcessedPacket.id).order_by(ProcessedPacket.id).limit(num_to_delete).subquery()
            
            # Execute a bulk delete on the subquery
            delete_query = db_session.query(ProcessedPacket).filter(ProcessedPacket.id.in_(subquery))
            delete_query.delete(synchronize_session=False)
            db_session.commit()

    finally:
        db_session.close()

async def prune_database_async(limit: int = 10000):
    """
    Asynchronously prunes the database by running the blocking prune function
    in a separate thread.
    """
    await asyncio.to_thread(prune_database, limit)

def get_all_packets() -> List[ProcessedPacket]:
    """
    Retrieves all processed packets from the database.
    """
    db_session = SessionLocal()
    try:
        packets = db_session.query(ProcessedPacket).all()
        return packets
    finally:
        db_session.close()

if __name__ == '__main__':
    # A simple script to initialize the DB and test inserting/reading data.
    init_db()

    all_packets = get_all_packets()
    print(f"Found {len(all_packets)} packets in the database.")
    for packet in all_packets:
        print(packet)

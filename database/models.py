# TODO: Explore using a more robust model definition library if complexity grows,
#       such as Pydantic with SQLAlchemy.

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base

# The Base which our ORM classes will inherit from.
Base = declarative_base()

class ProcessedPacket(Base):
    """
    SQLAlchemy ORM model for a processed network packet.

    This class defines the schema for the 'processed_packets' table,
    which will store the simplified packet information ready for display.
    """
    __tablename__ = 'processed_packets'

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ip = Column(String(50), nullable=True)
    destination_ip = Column(String(50), nullable=True)
    protocol_type = Column(String(10))
    summary = Column(String(255))
    timestamp = Column(String(50))

    def __repr__(self):
        return (
            f"<ProcessedPacket(id={self.id}, "
            f"src='{self.source_ip}', dst='{self.destination_ip}', "
            f"proto='{self.protocol_type}')>"
        )

# Example of how to create the database and table,
# which will be managed in the `db.py` module.
if __name__ == '__main__':
    # TODO: Make the database URL configurable, perhaps from a settings file.
    DATABASE_URL = "sqlite:///./packets.db"
    engine = create_engine(DATABASE_URL)

    print("Creating database and table 'processed_packets'...")
    Base.metadata.create_all(bind=engine)
    print("Done.")

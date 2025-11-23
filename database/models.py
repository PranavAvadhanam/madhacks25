# TODO: Explore using a more robust model definition library if complexity grows,
#       such as Pydantic with SQLAlchemy.

from sqlalchemy import Column, Integer, String, LargeBinary, create_engine, Text, DateTime
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
    protocol_type = Column(String(10)) # TCP, UDP, etc.
    
    # NEW COLUMNS
    service_name = Column(String(50)) # e.g., "HTTPS", "DNS", "Minecraft"
    traffic_direction = Column(String(10)) # "Upload" or "Download"
    
    # The "Human" Translation
    # e.g. "Initiating a secure connection to a web server."
    friendly_summary = Column(String(255)) 
    friendly_src = Column(String(255))
    friendly_dst = Column(String(255))
    
    # JSON string for the "Educational Mode" sidebar
    # e.g. '{"flag_explanation": "SYN means synchronize...", "port_explanation": "..."}'
    educational_data = Column(Text) 

    raw_packet = Column(LargeBinary)
    link_type = Column(String(50))
    timestamp = Column(DateTime)

    def __repr__(self):
        return (
            f"<ProcessedPacket(id={self.id}, "
            f"src='{self.source_ip}', dst='{self.destination_ip}', "
            f"proto='{self.protocol_type}', service='{self.service_name}')>"
        )

# Example of how to create the database and table,
# which will be managed in the `db.py` module.
if __name__ == '__main__':
    # TODO: Make the database URL configurable, perhaps from a settings file.
    DATABASE_URL = "sqlite:///./packets.db"
    engine = create_engine(DATABASE_URL)

    Base.metadata.create_all(bind=engine)

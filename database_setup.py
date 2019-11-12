from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    __tablename__ = 'categories'
    RELATIONSHIPS_TO_DICT = True
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User)
    items = relationship("Item")

    # Add add a decorator property to serialize data from the database
    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'items': [i.serialize for i in self.items],
            'name': self.name,
            'id': self.id,
        }


class Item(Base):
    __tablename__ = 'items'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String(750), nullable=False)
    category_id = Column(Integer, ForeignKey('categories.id'))
    category = relationship(Category)

    # Add add a decorator property to serialize data from the database
    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'category': self.category.name,

        }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)

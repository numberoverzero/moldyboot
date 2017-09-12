import enum
import uuid
from bloop import UUID, Column, Map, Integer
from bloop.ext.pendulum import DateTime

from .common import BaseModel, StringEnum, S3Location


class UserGame(BaseModel):
    class Meta:
        table_name = "users.games"
    user_id = Column(UUID, hash_key=True, name="u")
    game_id = Column(UUID, range_key=True, name="g")


class GameStatus(enum.Enum):
    CREATING = 0
    ACTIVE = 1
    COMPLETE = 2
    DELETED = 3


GameMetadata = Map(**{
    "created": DateTime,
    "status": StringEnum(GameStatus),
    "playerManifestLocation": S3Location,
    "gameStateLocation": S3Location
})


class Game(BaseModel):
    class Meta:
        table_name = "games"
    game_id = Column(UUID, hash_key=True, name="g")
    metadata = Column(GameMetadata)
    version = Column(Integer)

    @property
    def is_active(self):
        return self.metadata["status"] is GameStatus.ACTIVE

    def player_id_list(self, s3):
        obj = s3.get_object(**self.metadata["playerManifestLocation"])
        data = obj["Body"].read()
        return [
            uuid.UUID(line)
            for line in data.split("\n")
        ]


"""
game = controller.load_game(cf2b-)
for player_id in game.player_id_list(s3_client):

"""

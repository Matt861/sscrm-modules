from enum import Enum

class SoftwareType(Enum):
    DELIVERABLE = True
    TEST = False
    BUILD = False

class ExecutableSoftware(Enum):
    MAVEN = False
    PYPI = False
    NPM = False
    RAW = True
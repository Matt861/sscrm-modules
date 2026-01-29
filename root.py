# FILE IS USED TO FIND THE PROJECT ROOT, DO NOT MOVE FROM ROOT DIRECTORY
from pathlib import Path

p = Path(__file__).resolve()

def get_project_root():
    project_root_dir = Path(p.parent)
    return project_root_dir


if __name__ == '__main__':
    project_root = get_project_root()
import itertools

def edge_match_count(path1, path2):
    """
    TODO: Make it more efficient (not O(|path1||path2|))
    How many segments of path2 is in path1?

    A    PATH 1    B
    O=>>=O->>-O=>>=O
         |    |
         V    ^
         |    |
         O->>-O
         PATH 2

         ANS: 2 (shared two segments)
    """

    shared_segments = 0
    for i in range(len(path1)-1):
        for j in range(len(path2)-1):
            if path1[i] == path2[j] and path1[i+1] == path2[j+1]:
                shared_segments += 1
                break
    return shared_segments

def sort_path_list(primary, alt_paths):
    """
    Sorts list of alternative paths with respect to primary path
    """
    return sorted(alt_paths, key=lambda p: (edge_match_count(primary,p),len(p)))



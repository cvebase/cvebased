
def dedupe_sort(in_list):
    out_list = list(dict.fromkeys(in_list))
    out_list.sort()
    return out_list

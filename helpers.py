
def xor(variables: list[bool]):
    result = (variables[0] and not variables[1]) or (not variables[0] and variables[1])
    for i in range(2, len(variables)):
        result = (result and not variables[i]) or (not result and variables[i])
    return result
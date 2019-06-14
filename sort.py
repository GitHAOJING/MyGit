# -*- coding: utf-8 -*-
from __future__ import unicode_literals


def bubbleSort(ls):
    num = len(ls)
    for j in range(num - 1):
        for i in range(num - 1 - j):
            if ls[i] > ls[i + 1]:
                ls[i], ls[i + 1] = ls[i + 1], ls[i]
    return ls

ls = bubbleSort([2, 54, 2, 3, 1, 55])
print(ls)


def selectionSort(ls):
    for i in range(len(ls)):
        min_i = i
        for j in range(i + 1, len(ls)):
            if ls[min_i] > ls[j]:
                min_i = j
        if i != min_i:
            ls[i], ls[min_i] = ls[min_i], ls[i]
    return ls

ls = selectionSort([2, 6, 1, 7, 4, 3, 2, 3, 33])
print(ls)


def insertSort(ls):
    for i in range(1, len(ls)):
        j = i - 1
        current = ls[i]
        while j >= 0 and ls[j] > current:
            ls[j], ls[j + 1] = current, ls[j]
            j -= 1

    return ls

print(insertSort([2, 5, 2, 36, 3, 21, 1]))


def mergeSort(arr):
    # 1.sub_arr
    if len(arr) < 2:
        return arr
    middle = len(arr) // 2
    left, right = arr[0: middle], arr[middle:]
    # 2.merge
    return merge(mergeSort(left), mergeSort(right))


def merge(left, right):
    result = []
    while left and right:
        if left[0] <= right[0]:
            result.append(left.pop(0))
        else:
            result.append(right.pop(0))
    while left:
        result.append(left.pop(0))
    while right:
        result.append(right.pop(0))
    return result
print(mergeSort([33, 22, 5532, 12, 44, 22, 11, 3, 5, 1]))

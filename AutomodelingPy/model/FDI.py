from typing import List


class FDI(object):
    MAX_TEETH_COUNT: int = 32
    MAX_TEETH_NUM_PER_JAW_SIDE: int = MAX_TEETH_COUNT / 2

    UPPER_TEETH: List[int] = [18,  17,  16,  15,  14,  13,  12,  11,
                              21,  22,  23,  24,  25,  26,  27,  28]

    LOWER_TEETH: List[int] = [48,  47,  46,  45,  44,  43,  42,  41,
                              31,  32,  33,  34,  35,  36,  37,  38]

    ALL_TEETH: List[int] = list(UPPER_TEETH + LOWER_TEETH)

    MAX_LOWER_JAW_TOOTH: int = max(LOWER_TEETH)
    MIN_LOWER_JAW_TOOTH: int = min(LOWER_TEETH)

    MAX_UPPER_JAW_TOOTH: int = max(UPPER_TEETH)
    MIN_UPPER_JAW_TOOTH: int = min(UPPER_TEETH)

    @staticmethod
    def isLowerTooth(tooth_id: int) -> bool:
        if 19 == tooth_id or 20 == tooth_id:
            raise ValueError(f'Unexpected tooth_id value: {tooth_id}')
        return FDI.MIN_LOWER_JAW_TOOTH <= tooth_id <= FDI.MAX_LOWER_JAW_TOOTH

    @staticmethod
    def isUpperTooth(tooth_id: int) -> bool:
        if 39 == tooth_id or 40 == tooth_id:
            raise ValueError(f'Unexpected tooth_id value: {tooth_id}')
        return FDI.MIN_UPPER_JAW_TOOTH <= tooth_id <= FDI.MAX_UPPER_JAW_TOOTH

    @staticmethod
    def isLeftSideTooth(tooth_id: int):
        return (21 <= tooth_id <= 28) or (31 <= tooth_id <= 38)

    @staticmethod
    def isRightSideTooth(tooth_id: int):
        return (11 <= tooth_id <= 28) or (41 <= tooth_id <= 48)

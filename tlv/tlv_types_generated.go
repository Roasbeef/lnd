package tlv

import "fmt"

type TlvTypes interface {
	TlvType0 | TlvType1 | TlvType2 | TlvType3 | TlvType4 | TlvType5 | TlvType6 | TlvType7 | TlvType8 | TlvType9 | TlvType10 | TlvType11 | TlvType12 | TlvType13 | TlvType14 | TlvType15 | TlvType16 | TlvType17 | TlvType18 | TlvType19 | TlvType20 | TlvType21 | TlvType22 | TlvType23 | TlvType24 | TlvType25 | TlvType26 | TlvType27 | TlvType28 | TlvType29 | TlvType30 | TlvType31 | TlvType32 | TlvType33 | TlvType34 | TlvType35 | TlvType36 | TlvType37 | TlvType38 | TlvType39 | TlvType40 | TlvType41 | TlvType42 | TlvType43 | TlvType44 | TlvType45 | TlvType46 | TlvType47 | TlvType48 | TlvType49 | TlvType50 | TlvType51 | TlvType52 | TlvType53 | TlvType54 | TlvType55 | TlvType56 | TlvType57 | TlvType58 | TlvType59 | TlvType60 | TlvType61 | TlvType62 | TlvType63 | TlvType64 | TlvType65 | TlvType66 | TlvType67 | TlvType68 | TlvType69 | TlvType70 | TlvType71 | TlvType72 | TlvType73 | TlvType74 | TlvType75 | TlvType76 | TlvType77 | TlvType78 | TlvType79 | TlvType80 | TlvType81 | TlvType82 | TlvType83 | TlvType84 | TlvType85 | TlvType86 | TlvType87 | TlvType88 | TlvType89 | TlvType90 | TlvType91 | TlvType92 | TlvType93 | TlvType94 | TlvType95 | TlvType96 | TlvType97 | TlvType98 | TlvType99
}

func TlvTypeStruct(typeVal Type) TlvType {
	switch typeVal {
	case 0:
		return &TlvType0{}
	case 1:
		return &TlvType1{}
	case 2:
		return &TlvType2{}
	case 3:
		return &TlvType3{}
	case 4:
		return &TlvType4{}
	case 5:
		return &TlvType5{}
	case 6:
		return &TlvType6{}
	case 7:
		return &TlvType7{}
	case 8:
		return &TlvType8{}
	case 9:
		return &TlvType9{}
	case 10:
		return &TlvType10{}
	case 11:
		return &TlvType11{}
	case 12:
		return &TlvType12{}
	case 13:
		return &TlvType13{}
	case 14:
		return &TlvType14{}
	case 15:
		return &TlvType15{}
	case 16:
		return &TlvType16{}
	case 17:
		return &TlvType17{}
	case 18:
		return &TlvType18{}
	case 19:
		return &TlvType19{}
	case 20:
		return &TlvType20{}
	case 21:
		return &TlvType21{}
	case 22:
		return &TlvType22{}
	case 23:
		return &TlvType23{}
	case 24:
		return &TlvType24{}
	case 25:
		return &TlvType25{}
	case 26:
		return &TlvType26{}
	case 27:
		return &TlvType27{}
	case 28:
		return &TlvType28{}
	case 29:
		return &TlvType29{}
	case 30:
		return &TlvType30{}
	case 31:
		return &TlvType31{}
	case 32:
		return &TlvType32{}
	case 33:
		return &TlvType33{}
	case 34:
		return &TlvType34{}
	case 35:
		return &TlvType35{}
	case 36:
		return &TlvType36{}
	case 37:
		return &TlvType37{}
	case 38:
		return &TlvType38{}
	case 39:
		return &TlvType39{}
	case 40:
		return &TlvType40{}
	case 41:
		return &TlvType41{}
	case 42:
		return &TlvType42{}
	case 43:
		return &TlvType43{}
	case 44:
		return &TlvType44{}
	case 45:
		return &TlvType45{}
	case 46:
		return &TlvType46{}
	case 47:
		return &TlvType47{}
	case 48:
		return &TlvType48{}
	case 49:
		return &TlvType49{}
	case 50:
		return &TlvType50{}
	case 51:
		return &TlvType51{}
	case 52:
		return &TlvType52{}
	case 53:
		return &TlvType53{}
	case 54:
		return &TlvType54{}
	case 55:
		return &TlvType55{}
	case 56:
		return &TlvType56{}
	case 57:
		return &TlvType57{}
	case 58:
		return &TlvType58{}
	case 59:
		return &TlvType59{}
	case 60:
		return &TlvType60{}
	case 61:
		return &TlvType61{}
	case 62:
		return &TlvType62{}
	case 63:
		return &TlvType63{}
	case 64:
		return &TlvType64{}
	case 65:
		return &TlvType65{}
	case 66:
		return &TlvType66{}
	case 67:
		return &TlvType67{}
	case 68:
		return &TlvType68{}
	case 69:
		return &TlvType69{}
	case 70:
		return &TlvType70{}
	case 71:
		return &TlvType71{}
	case 72:
		return &TlvType72{}
	case 73:
		return &TlvType73{}
	case 74:
		return &TlvType74{}
	case 75:
		return &TlvType75{}
	case 76:
		return &TlvType76{}
	case 77:
		return &TlvType77{}
	case 78:
		return &TlvType78{}
	case 79:
		return &TlvType79{}
	case 80:
		return &TlvType80{}
	case 81:
		return &TlvType81{}
	case 82:
		return &TlvType82{}
	case 83:
		return &TlvType83{}
	case 84:
		return &TlvType84{}
	case 85:
		return &TlvType85{}
	case 86:
		return &TlvType86{}
	case 87:
		return &TlvType87{}
	case 88:
		return &TlvType88{}
	case 89:
		return &TlvType89{}
	case 90:
		return &TlvType90{}
	case 91:
		return &TlvType91{}
	case 92:
		return &TlvType92{}
	case 93:
		return &TlvType93{}
	case 94:
		return &TlvType94{}
	case 95:
		return &TlvType95{}
	case 96:
		return &TlvType96{}
	case 97:
		return &TlvType97{}
	case 98:
		return &TlvType98{}
	case 99:
		return &TlvType99{}
	default:
		return nil
	}
}

func GetTypeVal[T TlvTypes](t T) Type {
	switch any(t).(type) {
	case TlvType0:
		return 0
	case TlvType1:
		return 1
	case TlvType2:
		return 2
	case TlvType3:
		return 3
	case TlvType4:
		return 4
	case TlvType5:
		return 5
	case TlvType6:
		return 6
	case TlvType7:
		return 7
	case TlvType8:
		return 8
	case TlvType9:
		return 9
	case TlvType10:
		return 10
	case TlvType11:
		return 11
	case TlvType12:
		return 12
	case TlvType13:
		return 13
	case TlvType14:
		return 14
	case TlvType15:
		return 15
	case TlvType16:
		return 16
	case TlvType17:
		return 17
	case TlvType18:
		return 18
	case TlvType19:
		return 19
	case TlvType20:
		return 20
	case TlvType21:
		return 21
	case TlvType22:
		return 22
	case TlvType23:
		return 23
	case TlvType24:
		return 24
	case TlvType25:
		return 25
	case TlvType26:
		return 26
	case TlvType27:
		return 27
	case TlvType28:
		return 28
	case TlvType29:
		return 29
	case TlvType30:
		return 30
	case TlvType31:
		return 31
	case TlvType32:
		return 32
	case TlvType33:
		return 33
	case TlvType34:
		return 34
	case TlvType35:
		return 35
	case TlvType36:
		return 36
	case TlvType37:
		return 37
	case TlvType38:
		return 38
	case TlvType39:
		return 39
	case TlvType40:
		return 40
	case TlvType41:
		return 41
	case TlvType42:
		return 42
	case TlvType43:
		return 43
	case TlvType44:
		return 44
	case TlvType45:
		return 45
	case TlvType46:
		return 46
	case TlvType47:
		return 47
	case TlvType48:
		return 48
	case TlvType49:
		return 49
	case TlvType50:
		return 50
	case TlvType51:
		return 51
	case TlvType52:
		return 52
	case TlvType53:
		return 53
	case TlvType54:
		return 54
	case TlvType55:
		return 55
	case TlvType56:
		return 56
	case TlvType57:
		return 57
	case TlvType58:
		return 58
	case TlvType59:
		return 59
	case TlvType60:
		return 60
	case TlvType61:
		return 61
	case TlvType62:
		return 62
	case TlvType63:
		return 63
	case TlvType64:
		return 64
	case TlvType65:
		return 65
	case TlvType66:
		return 66
	case TlvType67:
		return 67
	case TlvType68:
		return 68
	case TlvType69:
		return 69
	case TlvType70:
		return 70
	case TlvType71:
		return 71
	case TlvType72:
		return 72
	case TlvType73:
		return 73
	case TlvType74:
		return 74
	case TlvType75:
		return 75
	case TlvType76:
		return 76
	case TlvType77:
		return 77
	case TlvType78:
		return 78
	case TlvType79:
		return 79
	case TlvType80:
		return 80
	case TlvType81:
		return 81
	case TlvType82:
		return 82
	case TlvType83:
		return 83
	case TlvType84:
		return 84
	case TlvType85:
		return 85
	case TlvType86:
		return 86
	case TlvType87:
		return 87
	case TlvType88:
		return 88
	case TlvType89:
		return 89
	case TlvType90:
		return 90
	case TlvType91:
		return 91
	case TlvType92:
		return 92
	case TlvType93:
		return 93
	case TlvType94:
		return 94
	case TlvType95:
		return 95
	case TlvType96:
		return 96
	case TlvType97:
		return 97
	case TlvType98:
		return 98
	case TlvType99:
		return 99
	default:
		panic(fmt.Sprintf("unknown type %T", t))
	}
}

type TlvType0 struct {}

func (t *TlvType0) typeVal() Type {
	return 0
}

type TlvType1 struct {}

func (t *TlvType1) typeVal() Type {
	return 1
}

type TlvType2 struct {}

func (t *TlvType2) typeVal() Type {
	return 2
}

type TlvType3 struct {}

func (t *TlvType3) typeVal() Type {
	return 3
}

type TlvType4 struct {}

func (t *TlvType4) typeVal() Type {
	return 4
}

type TlvType5 struct {}

func (t *TlvType5) typeVal() Type {
	return 5
}

type TlvType6 struct {}

func (t *TlvType6) typeVal() Type {
	return 6
}

type TlvType7 struct {}

func (t *TlvType7) typeVal() Type {
	return 7
}

type TlvType8 struct {}

func (t *TlvType8) typeVal() Type {
	return 8
}

type TlvType9 struct {}

func (t *TlvType9) typeVal() Type {
	return 9
}

type TlvType10 struct {}

func (t *TlvType10) typeVal() Type {
	return 10
}

type TlvType11 struct {}

func (t *TlvType11) typeVal() Type {
	return 11
}

type TlvType12 struct {}

func (t *TlvType12) typeVal() Type {
	return 12
}

type TlvType13 struct {}

func (t *TlvType13) typeVal() Type {
	return 13
}

type TlvType14 struct {}

func (t *TlvType14) typeVal() Type {
	return 14
}

type TlvType15 struct {}

func (t *TlvType15) typeVal() Type {
	return 15
}

type TlvType16 struct {}

func (t *TlvType16) typeVal() Type {
	return 16
}

type TlvType17 struct {}

func (t *TlvType17) typeVal() Type {
	return 17
}

type TlvType18 struct {}

func (t *TlvType18) typeVal() Type {
	return 18
}

type TlvType19 struct {}

func (t *TlvType19) typeVal() Type {
	return 19
}

type TlvType20 struct {}

func (t *TlvType20) typeVal() Type {
	return 20
}

type TlvType21 struct {}

func (t *TlvType21) typeVal() Type {
	return 21
}

type TlvType22 struct {}

func (t *TlvType22) typeVal() Type {
	return 22
}

type TlvType23 struct {}

func (t *TlvType23) typeVal() Type {
	return 23
}

type TlvType24 struct {}

func (t *TlvType24) typeVal() Type {
	return 24
}

type TlvType25 struct {}

func (t *TlvType25) typeVal() Type {
	return 25
}

type TlvType26 struct {}

func (t *TlvType26) typeVal() Type {
	return 26
}

type TlvType27 struct {}

func (t *TlvType27) typeVal() Type {
	return 27
}

type TlvType28 struct {}

func (t *TlvType28) typeVal() Type {
	return 28
}

type TlvType29 struct {}

func (t *TlvType29) typeVal() Type {
	return 29
}

type TlvType30 struct {}

func (t *TlvType30) typeVal() Type {
	return 30
}

type TlvType31 struct {}

func (t *TlvType31) typeVal() Type {
	return 31
}

type TlvType32 struct {}

func (t *TlvType32) typeVal() Type {
	return 32
}

type TlvType33 struct {}

func (t *TlvType33) typeVal() Type {
	return 33
}

type TlvType34 struct {}

func (t *TlvType34) typeVal() Type {
	return 34
}

type TlvType35 struct {}

func (t *TlvType35) typeVal() Type {
	return 35
}

type TlvType36 struct {}

func (t *TlvType36) typeVal() Type {
	return 36
}

type TlvType37 struct {}

func (t *TlvType37) typeVal() Type {
	return 37
}

type TlvType38 struct {}

func (t *TlvType38) typeVal() Type {
	return 38
}

type TlvType39 struct {}

func (t *TlvType39) typeVal() Type {
	return 39
}

type TlvType40 struct {}

func (t *TlvType40) typeVal() Type {
	return 40
}

type TlvType41 struct {}

func (t *TlvType41) typeVal() Type {
	return 41
}

type TlvType42 struct {}

func (t *TlvType42) typeVal() Type {
	return 42
}

type TlvType43 struct {}

func (t *TlvType43) typeVal() Type {
	return 43
}

type TlvType44 struct {}

func (t *TlvType44) typeVal() Type {
	return 44
}

type TlvType45 struct {}

func (t *TlvType45) typeVal() Type {
	return 45
}

type TlvType46 struct {}

func (t *TlvType46) typeVal() Type {
	return 46
}

type TlvType47 struct {}

func (t *TlvType47) typeVal() Type {
	return 47
}

type TlvType48 struct {}

func (t *TlvType48) typeVal() Type {
	return 48
}

type TlvType49 struct {}

func (t *TlvType49) typeVal() Type {
	return 49
}

type TlvType50 struct {}

func (t *TlvType50) typeVal() Type {
	return 50
}

type TlvType51 struct {}

func (t *TlvType51) typeVal() Type {
	return 51
}

type TlvType52 struct {}

func (t *TlvType52) typeVal() Type {
	return 52
}

type TlvType53 struct {}

func (t *TlvType53) typeVal() Type {
	return 53
}

type TlvType54 struct {}

func (t *TlvType54) typeVal() Type {
	return 54
}

type TlvType55 struct {}

func (t *TlvType55) typeVal() Type {
	return 55
}

type TlvType56 struct {}

func (t *TlvType56) typeVal() Type {
	return 56
}

type TlvType57 struct {}

func (t *TlvType57) typeVal() Type {
	return 57
}

type TlvType58 struct {}

func (t *TlvType58) typeVal() Type {
	return 58
}

type TlvType59 struct {}

func (t *TlvType59) typeVal() Type {
	return 59
}

type TlvType60 struct {}

func (t *TlvType60) typeVal() Type {
	return 60
}

type TlvType61 struct {}

func (t *TlvType61) typeVal() Type {
	return 61
}

type TlvType62 struct {}

func (t *TlvType62) typeVal() Type {
	return 62
}

type TlvType63 struct {}

func (t *TlvType63) typeVal() Type {
	return 63
}

type TlvType64 struct {}

func (t *TlvType64) typeVal() Type {
	return 64
}

type TlvType65 struct {}

func (t *TlvType65) typeVal() Type {
	return 65
}

type TlvType66 struct {}

func (t *TlvType66) typeVal() Type {
	return 66
}

type TlvType67 struct {}

func (t *TlvType67) typeVal() Type {
	return 67
}

type TlvType68 struct {}

func (t *TlvType68) typeVal() Type {
	return 68
}

type TlvType69 struct {}

func (t *TlvType69) typeVal() Type {
	return 69
}

type TlvType70 struct {}

func (t *TlvType70) typeVal() Type {
	return 70
}

type TlvType71 struct {}

func (t *TlvType71) typeVal() Type {
	return 71
}

type TlvType72 struct {}

func (t *TlvType72) typeVal() Type {
	return 72
}

type TlvType73 struct {}

func (t *TlvType73) typeVal() Type {
	return 73
}

type TlvType74 struct {}

func (t *TlvType74) typeVal() Type {
	return 74
}

type TlvType75 struct {}

func (t *TlvType75) typeVal() Type {
	return 75
}

type TlvType76 struct {}

func (t *TlvType76) typeVal() Type {
	return 76
}

type TlvType77 struct {}

func (t *TlvType77) typeVal() Type {
	return 77
}

type TlvType78 struct {}

func (t *TlvType78) typeVal() Type {
	return 78
}

type TlvType79 struct {}

func (t *TlvType79) typeVal() Type {
	return 79
}

type TlvType80 struct {}

func (t *TlvType80) typeVal() Type {
	return 80
}

type TlvType81 struct {}

func (t *TlvType81) typeVal() Type {
	return 81
}

type TlvType82 struct {}

func (t *TlvType82) typeVal() Type {
	return 82
}

type TlvType83 struct {}

func (t *TlvType83) typeVal() Type {
	return 83
}

type TlvType84 struct {}

func (t *TlvType84) typeVal() Type {
	return 84
}

type TlvType85 struct {}

func (t *TlvType85) typeVal() Type {
	return 85
}

type TlvType86 struct {}

func (t *TlvType86) typeVal() Type {
	return 86
}

type TlvType87 struct {}

func (t *TlvType87) typeVal() Type {
	return 87
}

type TlvType88 struct {}

func (t *TlvType88) typeVal() Type {
	return 88
}

type TlvType89 struct {}

func (t *TlvType89) typeVal() Type {
	return 89
}

type TlvType90 struct {}

func (t *TlvType90) typeVal() Type {
	return 90
}

type TlvType91 struct {}

func (t *TlvType91) typeVal() Type {
	return 91
}

type TlvType92 struct {}

func (t *TlvType92) typeVal() Type {
	return 92
}

type TlvType93 struct {}

func (t *TlvType93) typeVal() Type {
	return 93
}

type TlvType94 struct {}

func (t *TlvType94) typeVal() Type {
	return 94
}

type TlvType95 struct {}

func (t *TlvType95) typeVal() Type {
	return 95
}

type TlvType96 struct {}

func (t *TlvType96) typeVal() Type {
	return 96
}

type TlvType97 struct {}

func (t *TlvType97) typeVal() Type {
	return 97
}

type TlvType98 struct {}

func (t *TlvType98) typeVal() Type {
	return 98
}

type TlvType99 struct {}

func (t *TlvType99) typeVal() Type {
	return 99
}


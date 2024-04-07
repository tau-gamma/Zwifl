package onion.protocol;

public enum OnionPrivateMessageType {
	DATA(1),
	KEY_EXCHANGE_SUCCESS(2),
	EXTEND(3),
	COVER(4),
	SWITCH(5);

	private final int numVal;

	OnionPrivateMessageType(int numVal) {
		this.numVal = numVal;
	}

	public int getNumVal() {
		return numVal;
	}

	public static OnionPrivateMessageType fromValue(int numVal) throws KnouflException {
		for (OnionPrivateMessageType mtype : OnionPrivateMessageType.values()) {
			if (mtype.getNumVal() == numVal) {
				return mtype;
			}
		}
		throw new KnouflException("OnionPrivateMessageType not found: "+numVal);
	}

}

package onion.protocol;

public enum OnionPublicMessageType {
	
	PRIVATE(1),
	KEY_EXCHANGE(2),
	TEARDOWN_TUNNEL(3);
	
	
    private final int numVal;

    OnionPublicMessageType(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }
    
	public static OnionPublicMessageType fromValue(int numVal) throws KnouflException {
		for (OnionPublicMessageType mtype : OnionPublicMessageType.values()) {
			if (mtype.getNumVal() == numVal) {
				return mtype;
			}
		}
		throw new KnouflException("OnionPublicMessageType not found");
	}

}

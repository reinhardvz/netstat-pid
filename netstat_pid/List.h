
VOID
InitializeListHead(
	PLIST_ENTRY ListHead
	);

BOOL
IsListEmpty(
	PLIST_ENTRY ListHead
	);

VOID
RemoveEntryList(
	PLIST_ENTRY Entry
	);

PLIST_ENTRY
RemoveHeadList(
    PLIST_ENTRY ListHead
    );

PLIST_ENTRY
RemoveHeadListEx(
	PLIST_ENTRY Entry
	);

VOID
InsertTailList(
	PLIST_ENTRY ListHead,
	PLIST_ENTRY Entry
	);

VOID
InsertHeadList(
	PLIST_ENTRY ListHead,
	PLIST_ENTRY Entry
	);
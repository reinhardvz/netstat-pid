#include "stdafx.h"
#include "list.h"

VOID
InitializeListHead(
	PLIST_ENTRY ListHead
	)
{
	ListHead->Flink = ListHead->Blink = ListHead;
}

BOOL
IsListEmpty(
	PLIST_ENTRY ListHead
	)
{
	if(ListHead->Flink == ListHead)
		return TRUE;

	if(!ListHead->Flink && !ListHead->Blink)
		return TRUE;

	return FALSE;
}

VOID
RemoveEntryList(
	PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY _EX_Blink;
	PLIST_ENTRY _EX_Flink;

	_EX_Flink = Entry->Flink;
	_EX_Blink = Entry->Blink;

	_EX_Blink->Flink = _EX_Flink;
	_EX_Flink->Blink = _EX_Blink;
}

PLIST_ENTRY
RemoveHeadList(
    PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;

    return Entry;
}

PLIST_ENTRY
RemoveHeadListEx(
	PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY BeforeEntry;
	BeforeEntry = Entry->Blink;
	RemoveHeadList(BeforeEntry);
	return BeforeEntry;
}

VOID
InsertTailList(
	PLIST_ENTRY ListHead,
	PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY _EX_Blink;
	PLIST_ENTRY _EX_ListHead;

	_EX_ListHead = ListHead;
	_EX_Blink = _EX_ListHead->Blink;
	
	Entry->Flink = _EX_ListHead;
	Entry->Blink = _EX_Blink;
	
	_EX_Blink->Flink = Entry;
	_EX_ListHead->Blink = Entry;
}

VOID
InsertHeadList(
	PLIST_ENTRY ListHead,
	PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY _EX_Flink;
	PLIST_ENTRY _EX_ListHead;

	_EX_ListHead = ListHead;
	_EX_Flink = _EX_ListHead->Flink;

	Entry->Flink = _EX_Flink;
	Entry->Blink = _EX_ListHead;

	_EX_Flink->Blink = Entry;
	_EX_ListHead->Flink = Entry;
}


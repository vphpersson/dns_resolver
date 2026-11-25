package resolver

import (
	"context"
	"strings"

	dnsUtilsContext "github.com/altshiftab/dns_utils/pkg/context"
	dnsUtilsTypes "github.com/altshiftab/dns_utils/pkg/types"
	"github.com/miekg/dns"
)

// The log extractor of dns_utils writes every record of a message's answer
// section into the event, twice over: as a list of answers and joined into the
// message line. An answer of a few thousand addresses or of 60 KiB of TXT
// would make an event of that size for every query for the name, so what is
// logged is held to these bounds.
const (
	maxLoggedRecords    = 16
	maxLoggedRecordData = 256
)

const truncationMark = "..."

// loggable returns message, or, when its answer section is over the bounds, a
// copy holding the first maxLoggedRecords answers with each one's data cut to
// maxLoggedRecordData. The answer section is the only one the extractor reads.
// message itself is left as it is.
func loggable(message *dns.Msg) *dns.Msg {
	if message == nil {
		return nil
	}

	needsTrim := len(message.Answer) > maxLoggedRecords
	for _, record := range message.Answer {
		if needsTrim {
			break
		}
		needsTrim = record != nil && recordDataLength(record) > maxLoggedRecordData
	}
	if !needsTrim {
		return message
	}

	trimmed := *message
	answers := message.Answer[:min(len(message.Answer), maxLoggedRecords)]
	trimmed.Answer = make([]dns.RR, 0, len(answers))
	for _, record := range answers {
		if record != nil {
			trimmed.Answer = append(trimmed.Answer, loggableRecord(record))
		}
	}
	return &trimmed
}

// recordDataLength is the length of record's data alone: dns.Len counts the
// owner name and the fixed header too, which would have an ordinary address
// under a long name cut as if its data were long.
func recordDataLength(record dns.RR) int {
	return dns.Len(record) - dns.Len(&dns.RFC3597{Hdr: *record.Header()})
}

// loggableRecord returns record, or a stand-in of the same type and owner
// whose data is no longer than maxLoggedRecordData.
func loggableRecord(record dns.RR) dns.RR {
	if recordDataLength(record) <= maxLoggedRecordData {
		return record
	}

	header := *record.Header()
	switch typedRecord := record.(type) {
	case *dns.TXT:
		return &dns.TXT{Hdr: header, Txt: []string{truncateText(strings.Join(typedRecord.Txt, ""))}}
	case *dns.SPF:
		return &dns.SPF{Hdr: header, Txt: []string{truncateText(strings.Join(typedRecord.Txt, ""))}}
	case *dns.HTTPS:
		// The parameters are what makes one long; the priority and target
		// say what the record is.
		return &dns.HTTPS{SVCB: dns.SVCB{Hdr: header, Priority: typedRecord.Priority, Target: typedRecord.Target}}
	case *dns.SVCB:
		return &dns.SVCB{Hdr: header, Priority: typedRecord.Priority, Target: typedRecord.Target}
	default:
		// Of any other type, the type and owner are enough to tell what
		// was answered.
		return &dns.RFC3597{Hdr: header}
	}
}

func truncateText(text string) string {
	if len(text) <= maxLoggedRecordData {
		return text
	}
	return text[:maxLoggedRecordData-len(truncationMark)] + truncationMark
}

// trimLoggedMessages bounds the messages of the DnsContext ctx carries, which
// are what any later log event or error built on ctx writes out.
func trimLoggedMessages(ctx context.Context) {
	dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsContext == nil {
		return
	}
	dnsContext.QuestionMessage = loggable(dnsContext.QuestionMessage)
	dnsContext.AnswerMessage = loggable(dnsContext.AnswerMessage)
}

// forgetRejectedAnswer drops a reply that was read but refused from what is
// logged. The log takes the answer, when there is one, for the event's
// message, so a reply refused for its id or question would otherwise be
// logged as what was answered.
func forgetRejectedAnswer(ctx context.Context) {
	if dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext); ok && dnsContext != nil {
		dnsContext.AnswerMessage = nil
	}
}

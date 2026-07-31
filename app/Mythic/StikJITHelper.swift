import UIKit

/// Helper to enable JIT via StikDebug/StikJIT URL scheme.
/// Opens StikDebug with an embedded script, polls for CS_DEBUGGED,
/// then allocates JIT memory and detaches the debugger.
enum StikJITHelper {

    /// The JIT script. Edit mythic-jit.js, then run:
    ///   base64 -i app/Mythic/mythic-jit.js | tr -d '\n' | pbcopy
    /// and paste below. TODO: load from bundle resource instead.
    private static let scriptBase64 = "Ly8gTXl0aGljIEpJVCBTY3JpcHQgZm9yIFN0aWtEZWJ1ZwovLyBIYW5kbGVzIEJSSyAjMHhmMDBkICh1bml2ZXJzYWwgcHJvdG9jb2wpIHdpdGggeDE2LWJhc2VkIGNvbW1hbmQgZGlzcGF0Y2guCi8vCi8vIG1sMzQ2ICh2Mik6IHNvZnQtc2lnbmFsIHN0b3BzIChFWENfU09GVF9TSUdOQUwpIGZvcndhcmQgdGhlIE9SSUdJTkFMIHNpZ25vCi8vIGZyb20gbWVkYXRhWzFdIGFuZCBhcmUgbmV2ZXIgZ3VhcmRlZDsgcmF3IGZhdWx0IHN0b3BzIGZvcndhcmQgYSBtYXBwZWQKLy8gc2lnbmFsIHdpdGggYSBraWxsLW5vdC1kZXRhY2ggbGFzdCByZXNvcnQgKGRldGFjaCBsZWF2ZXMgdGhlIHRhc2sgcG9ydAovLyByZWdpc3RlcmVkIGJ1dCB1bnNlcnZpY2VkIC0+IHBhcmtlZCB0aHJlYWRzKS4KLy8gbWwzNDU6IG9ubHkgZ2VudWluZSBCUksgaW5zdHJ1Y3Rpb25zIGFyZSBza2lwcGVkIChwYys0KS4gVGhlIGRlYnVnZ2VyIGhvbGRzCi8vIHRoZSBUQVNLLWxldmVsIGV4Y2VwdGlvbiBwb3J0LCBzbyBldmVyeSBmYXVsdCB0aGUgYXBwJ3Mgb3duIE1hY2ggaGFuZGxlcgovLyBkZWNsaW5lcyAoS0VSTl9GQUlMVVJFKSBsYW5kcyBIRVJFIOKAlCB0aGUgb2xkICJBTFdBWVMgYWR2YW5jZSBQQyIgYmVoYXZpb3IKLy8gc2tpcC1zdGVwcGVkIHJlYWwgY3Jhc2hlcyBpbnN0cnVjdGlvbiBieSBpbnN0cnVjdGlvbiAoYW5kIHplcm9lZCB4MCksCi8vIHNpbGVudGx5IGNvcnJ1cHRpbmcgdGhyZWFkcyB1bnRpbCB0aGV5IHdhbmRlcmVkIGludG8gZGF0YSAobWwzNDQ6IGEKLy8gNCwwMDAtZmF1bHQgKzQgd2FsayB0aHJvdWdoIHNoYXJlZC1jYWNoZSBkYXRhIGVuZGluZyBpbiBhIGJvZ3VzIGd1ZXN0Ci8vIGV4Y2VwdGlvbikuIE5vbi1CUksgc3RvcHMgYXJlIG5vdyBoYW5kZWQgYmFjayB0byB0aGUgcHJvY2VzcyBhcyBhIHVuaXgKLy8gc2lnbmFsIHNvIHdpbmUncyBzaWdhY3Rpb24gaGFuZGxlcnMgcnVuOyBpZiB0aGUgc2lnbmFsIGNhbm5vdCBiZSBkZWxpdmVyZWQKLy8gdGhlIHNjcmlwdCBkZXRhY2hlcyBzbyB0aGUgcHJvY2VzcyBkaWVzIHZpc2libHkgaW5zdGVhZCBvZiB3YW5kZXJpbmcuCgpmdW5jdGlvbiBsaXR0bGVFbmRpYW5IZXhTdHJpbmdUb051bWJlcihoZXhTdHIpIHsKICAgIGNvbnN0IGJ5dGVzID0gW107CiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGhleFN0ci5sZW5ndGg7IGkgKz0gMikgewogICAgICAgIGJ5dGVzLnB1c2gocGFyc2VJbnQoaGV4U3RyLnN1YnN0cihpLCAyKSwgMTYpKTsKICAgIH0KICAgIGxldCBudW0gPSAwbjsKICAgIGZvciAobGV0IGkgPSA3OyBpID49IDA7IGktLSkgewogICAgICAgIG51bSA9IChudW0gPDwgOG4pIHwgQmlnSW50KGJ5dGVzW2ldIHx8IDApOwogICAgfQogICAgcmV0dXJuIG51bTsKfQoKZnVuY3Rpb24gbnVtYmVyVG9MaXR0bGVFbmRpYW5IZXhTdHJpbmcobnVtKSB7CiAgICBjb25zdCBieXRlcyA9IFtdOwogICAgZm9yIChsZXQgaSA9IDA7IGkgPCA4OyBpKyspIHsKICAgICAgICBieXRlcy5wdXNoKE51bWJlcihudW0gJiAweEZGbikpOwogICAgICAgIG51bSA+Pj0gOG47CiAgICB9CiAgICByZXR1cm4gYnl0ZXMubWFwKGIgPT4gYi50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKSkuam9pbignJyk7Cn0KCmZ1bmN0aW9uIGxpdHRsZUVuZGlhbkhleFRvVTMyKGhleFN0cikgewogICAgcmV0dXJuIHBhcnNlSW50KGhleFN0ci5tYXRjaCgvLi4vZykucmV2ZXJzZSgpLmpvaW4oJycpLCAxNik7Cn0KCmZ1bmN0aW9uIGV4dHJhY3RCcmtJbW1lZGlhdGUodTMyKSB7CiAgICByZXR1cm4gKHUzMiA+PiA1KSAmIDB4RkZGRjsKfQoKbGV0IHBpZCA9IGdldF9waWQoKTsKbG9nKGBNeXRoaWMgSklUOiBwaWQgPSAke3BpZH1gKTsKbGV0IGF0dGFjaFJlc3BvbnNlID0gc2VuZF9jb21tYW5kKGB2QXR0YWNoOyR7cGlkLnRvU3RyaW5nKDE2KX1gKTsKbG9nKGBNeXRoaWMgSklUOiBhdHRhY2hlZCA9ICR7YXR0YWNoUmVzcG9uc2V9YCk7CgovLyBtbDM1NTogU1RPUCBTRVJWSUNJTkcgQU5ZVEhJTkcgQlVUIEJSSy4KLy8KLy8gRXZlcnkgc2lnbmFsIGFuZCBmYXVsdCBzdG9wIGNvc3RzIHNldmVyYWwgc3luY2hyb25vdXMgcHJvdG9jb2wgcm91bmQtdHJpcHMKLy8gb24gU3Rpa0RlYnVnJ3Mgc2lkZS4gV2luZSBzaWduYWxzIGNvbnN0YW50bHkgKHRocmVhZCBzdXNwZW5kL3Jlc3VtZSksIHNvIHRoZQovLyB2MiBzY3JpcHQgYnVybmVkIDI3cyBDUFUgaW4gfjYwcyBhbmQgaU9TIGtpbGxlZCBTdGlrRGVidWcgaXRzZWxmIHdpdGggdGhlCi8vIHNjZW5lLXVwZGF0ZSB3YXRjaGRvZyAoMHg4QkFERjAwRCkg4oCUIHdoaWNoIHRvcmUgZG93biB0aGUgZGVidWcgc2Vzc2lvbiBhbmQKLy8gbGVmdCBNeXRoaWMgdG8gYmUgU0lHS0lMTGVkIHdpdGggbm8gY3Jhc2ggcmVwb3J0LiBUaGF0IGlzIHRoZSAiaW5zdGFudAovLyB2YW5pc2gsIGVtcHR5IFN0aWtEZWJ1ZyBsb2ciIHRoZSB1c2VyIGtlcHQgc2VlaW5nLgovLwovLyBCb3RoIHBhY2tldHMgYmVsb3cgYXJlIGJlc3QtZWZmb3J0OyBvbiBhbiBvbGRlciBzdHViIHRoZXkgc2ltcGx5IGZhaWwgYW5kCi8vIHRoZSBmYXVsdC9zaWduYWwgcGF0aHMgZnVydGhlciBkb3duIHN0aWxsIHdvcmsgYXMgYmVmb3JlLgovLyAgIFFTZXRJZ25vcmVkRXhjZXB0aW9ucyDigJQgZGVidWdzZXJ2ZXIgc3RvcHMgaW50ZXJjZXB0aW5nIHRoZXNlIE1hY2gKLy8gICAgIGV4Y2VwdGlvbnMsIHNvIHRoZXkgcmVhY2ggdGhlIGFwcCdzIE9XTiBoYW5kbGVycyAod2luZSByZWdpc3RlcnMKLy8gICAgIHRocmVhZC1sZXZlbCBwb3J0cyBmb3IgQkFEX0FDQ0VTUytCQURfSU5TVFJVQ1RJT04sIGFuZCBhbnl0aGluZyBpdAovLyAgICAgZGVjbGluZXMgYmVjb21lcyBhIG5vcm1hbCBCU0Qgc2lnbmFsIGludG8gd2luZSdzIHNpZ2FjdGlvbiBoYW5kbGVycykuCi8vICAgUVBhc3NTaWduYWxzIOKAlCBkZWxpdmVyIHNpZ25hbHMgdG8gdGhlIGluZmVyaW9yIHdpdGhvdXQgc3RvcHBpbmcuIFNJR1RSQVAKLy8gICAgIGlzIGRlbGliZXJhdGVseSBFWENMVURFRDogQlJLIGFycml2ZXMgdGhhdCB3YXkgYW5kIGlzIG91ciB3aG9sZSBqb2IuCnsKICAgIGxldCBpZ24gPSBzZW5kX2NvbW1hbmQoYFFTZXRJZ25vcmVkRXhjZXB0aW9uczpFWENfQkFEX0FDQ0VTUztFWENfQkFEX0lOU1RSVUNUSU9OYCk7CiAgICBsb2coYE15dGhpYyBKSVQ6IFFTZXRJZ25vcmVkRXhjZXB0aW9ucyAtPiAke2lnbiB8fCAnKHVuc3VwcG9ydGVkKSd9YCk7CiAgICBsZXQgc2lncyA9IFtdOwogICAgZm9yIChsZXQgcyA9IDE7IHMgPD0gMzE7IHMrKykgaWYgKHMgIT09IDUpIHNpZ3MucHVzaChzLnRvU3RyaW5nKDE2KSk7CiAgICBsZXQgcGFzcyA9IHNlbmRfY29tbWFuZChgUVBhc3NTaWduYWxzOiR7c2lncy5qb2luKCc7Jyl9YCk7CiAgICBsb2coYE15dGhpYyBKSVQ6IFFQYXNzU2lnbmFscyAtPiAke3Bhc3MgfHwgJyh1bnN1cHBvcnRlZCknfWApOwp9CgpsZXQgZGV0YWNoZWQgPSBmYWxzZTsKbGV0IHBlbmRpbmcgPSBudWxsOyAgICAgICAgLy8gc3RvcCBwYWNrZXQgcmV0dXJuZWQgYnkgYSBjb250aW51ZSB3ZSBhbHJlYWR5IHNlbnQKbGV0IGxhc3RGYXVsdEtleSA9IG51bGw7ICAgLy8gInRpZDpwYyIgb2YgdGhlIGxhc3Qgbm9uLUJSSyBzdG9wCmxldCBmYXVsdFJlcGVhdHMgPSAwOwpsZXQgZmF1bHRMb2dzID0gMDsKbGV0IHNpZ0xvZ3MgPSAwOwovLyBIYXJkIGNlaWxpbmcgb24gVUkgbG9nIGxpbmVzOiBlYWNoIGxvZygpIGRyaXZlcyBhIFN3aWZ0VUkgdXBkYXRlLCBhbmQgaXQgaXMKLy8gc2NlbmUtdXBkYXRlIHN0YWxscyB0aGF0IHRoZSB3YXRjaGRvZyBraWxscyBmb3IuIFVzZSB1bG9nKCkgZXZlcnl3aGVyZQovLyBpbnNpZGUgdGhlIHN0b3AgbG9vcDsgYmFyZSBsb2coKSBvbmx5IGZvciB0aGUgZmV3IHN0YXJ0dXAgbGluZXMuCmxldCBsb2dCdWRnZXQgPSA0MDsKZnVuY3Rpb24gdWxvZyhtc2cpIHsgaWYgKGxvZ0J1ZGdldCA+IDApIHsgbG9nQnVkZ2V0LS07IGxvZyhtc2cpOyB9IH0KCmZ1bmN0aW9uIGxvb2tzTGlrZVN0b3AocmVzcCkgewogICAgcmV0dXJuIHR5cGVvZiByZXNwID09PSAnc3RyaW5nJyAmJiAvXltUU1dYXS8udGVzdChyZXNwKTsKfQoKLy8gRm9yd2FyZCBhIHVuaXggc2lnbmFsIHRvIHRoZSBzdG9wcGVkIHRocmVhZCBhbmQgcmVtZW1iZXIgdGhlIG5leHQgc3RvcC4KLy8gUmV0dXJucyB0cnVlIGlmIHRoZSBjb250aW51ZSB3YXMgYWNjZXB0ZWQuCmZ1bmN0aW9uIGZvcndhcmRTaWduYWwoc2lnLCB0aWQpIHsKICAgIGxldCBzaWdIZXggPSBzaWcudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJyk7CiAgICBsZXQgcmVzcCA9IHNlbmRfY29tbWFuZChgdkNvbnQ7QyR7c2lnSGV4fToke3RpZH07Y2ApOwogICAgaWYgKCFsb29rc0xpa2VTdG9wKHJlc3ApKSB7CiAgICAgICAgcmVzcCA9IHNlbmRfY29tbWFuZChgQyR7c2lnSGV4fWApOwogICAgfQogICAgaWYgKGxvb2tzTGlrZVN0b3AocmVzcCkpIHsKICAgICAgICBwZW5kaW5nID0gcmVzcDsKICAgICAgICByZXR1cm4gdHJ1ZTsKICAgIH0KICAgIHJldHVybiBmYWxzZTsKfQoKd2hpbGUgKCFkZXRhY2hlZCkgewogICAgbGV0IGJya1Jlc3BvbnNlID0gcGVuZGluZyAhPT0gbnVsbCA/IHBlbmRpbmcgOiBzZW5kX2NvbW1hbmQoYGNgKTsKICAgIHBlbmRpbmcgPSBudWxsOwoKICAgIC8vIFcvWCA9IGluZmVyaW9yIGV4aXRlZDsgbm90aGluZyBsZWZ0IHRvIGRlYnVnLgogICAgaWYgKHR5cGVvZiBicmtSZXNwb25zZSA9PT0gJ3N0cmluZycgJiYgL15bV1hdLy50ZXN0KGJya1Jlc3BvbnNlKSkgewogICAgICAgIHVsb2coYE15dGhpYyBKSVQ6IGluZmVyaW9yIGV4aXRlZCAoJHticmtSZXNwb25zZX0pYCk7CiAgICAgICAgZGV0YWNoZWQgPSB0cnVlOwogICAgICAgIGNvbnRpbnVlOwogICAgfQoKICAgIGxldCB0aWRNYXRjaCA9IC9UWzAtOWEtZl0rdGhyZWFkOig/PHRpZD5bMC05YS1mXSspOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgdGlkID0gdGlkTWF0Y2ggPyB0aWRNYXRjaC5ncm91cHNbJ3RpZCddIDogbnVsbDsKICAgIGxldCBwY01hdGNoID0gLzIwOig/PHJlZz5bMC05YS1mXXsxNn0pOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgcGMgPSBwY01hdGNoID8gcGNNYXRjaC5ncm91cHNbJ3JlZyddIDogbnVsbDsKCiAgICBpZiAoIXRpZCB8fCAhcGMpIHsKICAgICAgICB1bG9nKGBNeXRoaWMgSklUOiBmYWlsZWQgdG8gcGFyc2UsIGNvbnRpbnVpbmdgKTsKICAgICAgICBjb250aW51ZTsKICAgIH0KCiAgICBsZXQgcGNOdW0gPSBsaXR0bGVFbmRpYW5IZXhTdHJpbmdUb051bWJlcihwYyk7CgogICAgLy8gbWVkYXRhIHZhbHVlcyBhcmUgaGV4IFdJVEhPVVQgMHggcHJlZml4IChtbDM0NSBydW46IEVYQ19TT0ZUX1NJR05BTAogICAgLy8gcHJpbnRlZCBhcyAiMTAwMDMiKS4gbWV0eXBlIGlzIGEgc21hbGwgaW50ZWdlciwgc2FtZSBlaXRoZXIgd2F5LgogICAgbGV0IG1ldHlwZU1hdGNoID0gL21ldHlwZTooWzAtOWEtZl0rKTsvLmV4ZWMoYnJrUmVzcG9uc2UpOwogICAgbGV0IG1ldHlwZSA9IG1ldHlwZU1hdGNoID8gcGFyc2VJbnQobWV0eXBlTWF0Y2hbMV0sIDE2KSA6IDA7CiAgICBsZXQgbWVkYXRhID0gW107CiAgICBsZXQgbXJlID0gL21lZGF0YTooWzAtOWEtZnhdKyk7L2csIG1tOwogICAgd2hpbGUgKChtbSA9IG1yZS5leGVjKGJya1Jlc3BvbnNlKSkgIT09IG51bGwpIG1lZGF0YS5wdXNoKHBhcnNlSW50KG1tWzFdLCAxNikpOwoKICAgIC8vIEVYQ19TT0ZUV0FSRSAvIEVYQ19TT0ZUX1NJR05BTCAobWV0eXBlIDUsIG1lZGF0YVswXT0weDEwMDAzKTogdGhlCiAgICAvLyBrZXJuZWwgaXMgcm91dGluZyBhIHVuaXggU0lHTkFMIHRocm91Z2ggdGhlIGRlYnVnZ2VyIOKAlCBwdGhyZWFkX2tpbGwsCiAgICAvLyB3aW5lJ3Mgc3VzcGVuZCBzaWduYWxzLCBmYXVsdC1jb252ZXJzaW9uIHNpZ25hbHMsIGFsbCBvZiBpdC4gVGhpcyBpcwogICAgLy8gbm90IGEgZmF1bHQgYW5kIG5vdCBvdXJzIHRvIGp1ZGdlOiBmb3J3YXJkIHRoZSBPUklHSU5BTCBzaWdubwogICAgLy8gKG1lZGF0YVsxXSkgdW50b3VjaGVkLCBuZXZlciBjb3VudCByZXBlYXRzICh3aW5lIGxlZ2l0aW1hdGVseSByZXRyaWVzCiAgICAvLyBzYW1lLXBjIGZhdWx0cyksIG5ldmVyIGRldGFjaC4gdjEgbWlzZGVsaXZlcmVkIHRoZXNlIGFzIFNJR1NFR1YgYW5kCiAgICAvLyB0aGVuIGRldGFjaGVkIG9uIHdpbmUncyBib290LXRpbWUgcmV0cnkgbG9vcCAobWwzNDUpLgogICAgaWYgKG1ldHlwZSA9PT0gNSkgewogICAgICAgIGxldCBzaWdubyA9IChtZWRhdGEubGVuZ3RoID4gMSAmJiBtZWRhdGFbMV0gPj0gMSAmJiBtZWRhdGFbMV0gPD0gMzEpID8gbWVkYXRhWzFdIDogMDsKICAgICAgICBpZiAoc2lnTG9ncyA8IDggfHwgKHNpZ0xvZ3MgJSA1MDApID09PSAwKSB7CiAgICAgICAgICAgIHVsb2coYE15dGhpYyBKSVQ6IHNvZnQtc2lnbmFsIHRpZD0ke3RpZH0gcGM9MHgke3BjTnVtLnRvU3RyaW5nKDE2KX0gYCArCiAgICAgICAgICAgICAgICBgc2lnbm89JHtzaWdubyB8fCAnPyd9ICgjJHtzaWdMb2dzfSlgKTsKICAgICAgICB9CiAgICAgICAgc2lnTG9ncysrOwogICAgICAgIGlmIChzaWdubyA9PT0gMCB8fCAhZm9yd2FyZFNpZ25hbChzaWdubywgdGlkKSkgewogICAgICAgICAgICAvLyBVbmtub3duIHNpZ25vIG9yIEMgdW5zdXBwb3J0ZWQ6IHBsYWluIGNvbnRpbnVlIGFuZCB0cnVzdCB0aGUKICAgICAgICAgICAgLy8gc3R1YiB0byBkZWxpdmVyIHRoZSBwZW5kaW5nIHNpZ25hbCBvbiByZXN1bWUuCiAgICAgICAgICAgIGxldCByZXNwID0gc2VuZF9jb21tYW5kKGBjYCk7CiAgICAgICAgICAgIGlmIChsb29rc0xpa2VTdG9wKHJlc3ApKSBwZW5kaW5nID0gcmVzcDsKICAgICAgICB9CiAgICAgICAgY29udGludWU7CiAgICB9CgogICAgbGV0IGluc3RySGV4ID0gc2VuZF9jb21tYW5kKGBtJHtwY051bS50b1N0cmluZygxNil9LDRgKTsKICAgIGxldCBpbnNuT2sgPSB0eXBlb2YgaW5zdHJIZXggPT09ICdzdHJpbmcnICYmIC9eWzAtOWEtZkEtRl17OH0kLy50ZXN0KGluc3RySGV4KTsKICAgIGxldCBpbnN0clUzMiA9IGluc25PayA/IGxpdHRsZUVuZGlhbkhleFRvVTMyKGluc3RySGV4KSA6IDA7CiAgICAvLyBCUksgI2ltbTE2ID0gMTEwMSAwMTAwIDAwMSBpbW0xNiAwMDAwMAogICAgbGV0IGlzQnJrID0gaW5zbk9rICYmICgoaW5zdHJVMzIgJiAweEZGRTAwMDFGKSA+Pj4gMCkgPT09IDB4RDQyMDAwMDA7CgogICAgaWYgKCFpc0JyaykgewogICAgICAgIC8vIEEgcmF3IGZhdWx0IHN0b3AgZXNjYWxhdGVkIHBhc3QgdGhlIGFwcCdzIE1hY2ggaGFuZGxlci4gTmV2ZXIgc2tpcAogICAgICAgIC8vIGl0LiBEZWxpdmVyIGl0IGJhY2sgdG8gdGhlIHByb2Nlc3MgYXMgYSB1bml4IHNpZ25hbCBzbyB0aGUgYXBwJ3MKICAgICAgICAvLyBzaWdhY3Rpb24gaGFuZGxlcnMgKHdpbmUgc2Vndi9idXMvaWxsKSBnZXQgYW4gaG9uZXN0IHNob3QgYXQgaXQuCiAgICAgICAgbGV0IGtleSA9IGAke3RpZH06JHtwY31gOwogICAgICAgIGZhdWx0UmVwZWF0cyA9IChrZXkgPT09IGxhc3RGYXVsdEtleSkgPyBmYXVsdFJlcGVhdHMgKyAxIDogMTsKICAgICAgICBsYXN0RmF1bHRLZXkgPSBrZXk7CgogICAgICAgIGxldCBrY29kZSA9IG1lZGF0YS5sZW5ndGggPiAwID8gbWVkYXRhWzBdIDogMDsKICAgICAgICBsZXQgc2lnID0gMTE7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIFNJR1NFR1YgZGVmYXVsdAogICAgICAgIGlmIChtZXR5cGUgPT09IDEpIHNpZyA9IChrY29kZSA9PT0gMSkgPyAxMSA6IDEwOyAvLyBCQURfQUNDRVNTOiBJTlZBTElE4oaSU0VHViwgUFJPVOKGkkJVUwogICAgICAgIGVsc2UgaWYgKG1ldHlwZSA9PT0gMikgc2lnID0gNDsgICAgICAgICAgICAgICAgLy8gQkFEX0lOU1RSVUNUSU9OIOKGkiBTSUdJTEwKICAgICAgICBlbHNlIGlmIChtZXR5cGUgPT09IDMpIHNpZyA9IDg7ICAgICAgICAgICAgICAgIC8vIEFSSVRITUVUSUMg4oaSIFNJR0ZQRQogICAgICAgIGVsc2UgaWYgKG1ldHlwZSA9PT0gNikgc2lnID0gNTsgICAgICAgICAgICAgICAgLy8gQlJFQUtQT0lOVCAobm9uLUJSSykg4oaSIFNJR1RSQVAKCiAgICAgICAgaWYgKGZhdWx0TG9ncyA8IDE2KSB7CiAgICAgICAgICAgIGZhdWx0TG9ncysrOwogICAgICAgICAgICB1bG9nKGBNeXRoaWMgSklUOiBmYXVsdCAobm90IEJSSykgdGlkPSR7dGlkfSBwYz0weCR7cGNOdW0udG9TdHJpbmcoMTYpfSBgICsKICAgICAgICAgICAgICAgIGBpbnNuPSR7aW5zbk9rID8gaW5zdHJVMzIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDgsICcwJykgOiBgPCR7aW5zdHJIZXh9PmB9IGAgKwogICAgICAgICAgICAgICAgYG1ldHlwZT0ke21ldHlwZX0ga2NvZGU9JHtrY29kZS50b1N0cmluZygxNil9IC0+IHNpZyAke3NpZ30gKHJlcGVhdCAke2ZhdWx0UmVwZWF0c30pYCk7CiAgICAgICAgfQoKICAgICAgICAvLyBORVZFUiBkZXRhY2ggaGVyZTogd2l0aCB0aGUgU3Rpa0RlYnVnIHdpbmRvdyBzdGlsbCBvcGVuIHRoZSB0YXNrCiAgICAgICAgLy8gZXhjZXB0aW9uIHBvcnQgc3RheXMgcmVnaXN0ZXJlZCBidXQgdW5zZXJ2aWNlZCwgYW5kIGV2ZXJ5IGxhdGVyCiAgICAgICAgLy8gZXNjYWxhdGVkIGZhdWx0IHBhcmtzIGl0cyB0aHJlYWQgZm9yZXZlciAobWwzNDUgd2VkZ2VkIHN0ZWFtLmV4ZSdzCiAgICAgICAgLy8gbWFpbiB0aHJlYWQgZXhhY3RseSB0aGlzIHdheSkuIElmIHRoZSBmYXVsdCB0cnVseSBjYW5ub3QgYmUKICAgICAgICAvLyBkZWxpdmVyZWQsIGtpbGwgdGhlIGluZmVyaW9yIOKAlCBhIHZpc2libGUgZGVhdGggd2l0aCBsb2dzIGludGFjdC4KICAgICAgICBpZiAoZmF1bHRSZXBlYXRzID49IDgpIHsKICAgICAgICAgICAgdWxvZyhgTXl0aGljIEpJVDogZmF1bHQgYXQgcGM9MHgke3BjTnVtLnRvU3RyaW5nKDE2KX0gdW5kZWxpdmVyYWJsZSBhZnRlciBgICsKICAgICAgICAgICAgICAgIGAke2ZhdWx0UmVwZWF0c30gdHJpZXMg4oCUIGtpbGxpbmcgaW5mZXJpb3IgKHZpc2libGUgZGVhdGggYmVhdHMgYSBwYXJrZWQgdGhyZWFkKWApOwogICAgICAgICAgICBzZW5kX2NvbW1hbmQoYGtgKTsKICAgICAgICAgICAgZGV0YWNoZWQgPSB0cnVlOwogICAgICAgICAgICBjb250aW51ZTsKICAgICAgICB9CgogICAgICAgIGlmICghZm9yd2FyZFNpZ25hbChzaWcsIHRpZCkpIHsKICAgICAgICAgICAgLy8gRm9yd2FyZGluZyByZWplY3RlZDogcGxhaW4gY29udGludWU7IGlmIHRoZSBzYW1lIHN0b3AgcmVjdXJzCiAgICAgICAgICAgIC8vIHRoZSBndWFyZCBhYm92ZSBldmVudHVhbGx5IGtpbGxzLgogICAgICAgICAgICBsZXQgcmVzcCA9IHNlbmRfY29tbWFuZChgY2ApOwogICAgICAgICAgICBpZiAobG9va3NMaWtlU3RvcChyZXNwKSkgcGVuZGluZyA9IHJlc3A7CiAgICAgICAgfQogICAgICAgIGNvbnRpbnVlOwogICAgfQoKICAgIC8vIEdlbnVpbmUgQlJLIGZyb20gaGVyZSBvbiDigJQgdGhlIHByb3RvY29sIHBhdGguCiAgICBsYXN0RmF1bHRLZXkgPSBudWxsOwogICAgZmF1bHRSZXBlYXRzID0gMDsKCiAgICBsZXQgYnJrSW1tID0gZXh0cmFjdEJya0ltbWVkaWF0ZShpbnN0clUzMik7CgogICAgLy8gQWR2YW5jZSBQQyBwYXN0IHRoZSBCUksgc28gaXQgY2Fubm90IHJlLWZpcmUKICAgIGxldCBwY1BsdXM0ID0gbnVtYmVyVG9MaXR0bGVFbmRpYW5IZXhTdHJpbmcocGNOdW0gKyA0bik7CiAgICBzZW5kX2NvbW1hbmQoYFAyMD0ke3BjUGx1czR9O3RocmVhZDoke3RpZH07YCk7CgogICAgbGV0IHgxNk1hdGNoID0gLzEwOig/PHJlZz5bMC05YS1mXXsxNn0pOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgeDE2ID0geDE2TWF0Y2ggPyB4MTZNYXRjaC5ncm91cHNbJ3JlZyddIDogbnVsbDsKCiAgICAvLyBTa2lwIHVua25vd24gQlJLIGltbWVkaWF0ZXMgKFBDIGFscmVhZHkgYWR2YW5jZWQpCiAgICBpZiAoKGJya0ltbSAhPT0gMHhmMDBkICYmIGJya0ltbSAhPT0gMHg2OSkgfHwgIXgxNikgewogICAgICAgIC8vIFNldCB4MD0wIChmYWlsdXJlL3NraXAgaW5kaWNhdG9yKSBzbyBhcHAncyBTSUdUUkFQIGZhbGxiYWNrIHdvcmtzCiAgICAgICAgc2VuZF9jb21tYW5kKGBQMD0ke251bWJlclRvTGl0dGxlRW5kaWFuSGV4U3RyaW5nKDBuKX07dGhyZWFkOiR7dGlkfTtgKTsKICAgICAgICBjb250aW51ZTsKICAgIH0KCiAgICB1bG9nKGBNeXRoaWMgSklUOiBCUksgIzB4JHticmtJbW0udG9TdHJpbmcoMTYpfWApOwoKICAgIC8vIFBhcnNlIHgwIGFuZCB4MQogICAgbGV0IHgwTWF0Y2ggPSAvMDA6KD88cmVnPlswLTlhLWZdezE2fSk7Ly5leGVjKGJya1Jlc3BvbnNlKTsKICAgIGxldCB4MU1hdGNoID0gLzAxOig/PHJlZz5bMC05YS1mXXsxNn0pOy8uZXhlYyhicmtSZXNwb25zZSk7CiAgICBsZXQgeDAgPSB4ME1hdGNoID8gbGl0dGxlRW5kaWFuSGV4U3RyaW5nVG9OdW1iZXIoeDBNYXRjaC5ncm91cHNbJ3JlZyddKSA6IDBuOwogICAgbGV0IHgxID0geDFNYXRjaCA/IGxpdHRsZUVuZGlhbkhleFN0cmluZ1RvTnVtYmVyKHgxTWF0Y2guZ3JvdXBzWydyZWcnXSkgOiAwbjsKICAgIGxldCB4MTZOdW0gPSBsaXR0bGVFbmRpYW5IZXhTdHJpbmdUb051bWJlcih4MTYpOwoKICAgIGlmIChicmtJbW0gPT09IDB4ZjAwZCkgewogICAgICAgIHVsb2coYE15dGhpYyBKSVQ6IHgxNiA9ICR7eDE2TnVtfWApOwoKICAgICAgICBpZiAoeDE2TnVtID09PSAwbikgewogICAgICAgICAgICAvLyBDTURfREVUQUNICiAgICAgICAgICAgIHVsb2coYE15dGhpYyBKSVQ6IGRldGFjaGApOwogICAgICAgICAgICBzZW5kX2NvbW1hbmQoYERgKTsKICAgICAgICAgICAgZGV0YWNoZWQgPSB0cnVlOwoKICAgICAgICB9IGVsc2UgaWYgKHgxNk51bSA9PT0gMW4pIHsKICAgICAgICAgICAgLy8gQ01EX1BSRVBBUkVfUkVHSU9OCiAgICAgICAgICAgIHVsb2coYE15dGhpYyBKSVQ6IHByZXBhcmUgYWRkcj0weCR7eDAudG9TdHJpbmcoMTYpfSBzaXplPTB4JHt4MS50b1N0cmluZygxNil9YCk7CgogICAgICAgICAgICBsZXQgYWRkciA9IHgwOwogICAgICAgICAgICBpZiAoeDAgPT09IDBuICYmIHgxICE9PSAwbikgewogICAgICAgICAgICAgICAgbGV0IGFsbG9jUmVzcCA9IHNlbmRfY29tbWFuZChgX00ke3gxLnRvU3RyaW5nKDE2KX0scnhgKTsKICAgICAgICAgICAgICAgIGlmIChhbGxvY1Jlc3AgJiYgYWxsb2NSZXNwLmxlbmd0aCA+IDApIHsKICAgICAgICAgICAgICAgICAgICBhZGRyID0gQmlnSW50KGAweCR7YWxsb2NSZXNwfWApOwogICAgICAgICAgICAgICAgICAgIHVsb2coYE15dGhpYyBKSVQ6IGFsbG9jYXRlZCBhdCAweCR7YWRkci50b1N0cmluZygxNil9YCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIGlmIChhZGRyICE9PSAwbiAmJiB4MSAhPT0gMG4pIHsKICAgICAgICAgICAgICAgIGxldCBwcmVwUmVzcCA9IHByZXBhcmVfbWVtb3J5X3JlZ2lvbihhZGRyLCB4MSk7CiAgICAgICAgICAgICAgICB1bG9nKGBNeXRoaWMgSklUOiBwcmVwYXJlZCA9ICR7cHJlcFJlc3B9YCk7CiAgICAgICAgICAgIH0KCiAgICAgICAgICAgIHNlbmRfY29tbWFuZChgUDA9JHtudW1iZXJUb0xpdHRsZUVuZGlhbkhleFN0cmluZyhhZGRyKX07dGhyZWFkOiR7dGlkfTtgKTsKCiAgICAgICAgfSBlbHNlIGlmICh4MTZOdW0gPT09IDNuKSB7CiAgICAgICAgICAgIC8vIENNRF9NQVBfUEFHRV9aRVJPOiBNYXAgYSBwYWdlIGF0IGFkZHJlc3MgMCB3aXRoIFRFQiBkYXRhLgogICAgICAgICAgICAvLyB4MCA9IFRFQiBhZGRyZXNzLCB4MSA9IHNpemUgKDB4NDAwMCA9IDE2S0IgaU9TIHBhZ2UpCiAgICAgICAgICAgIC8vIFRoZSBhcHAgY2FuJ3QgbWFwIHBhZ2UgMCBpdHNlbGYgKGtlcm5lbCByZWZ1c2VzKS4gVGhlIGRlYnVnZ2VyCiAgICAgICAgICAgIC8vIG1heSBoYXZlIGRpZmZlcmVudCBwcml2aWxlZ2VzIHRvIGNyZWF0ZSB0aGlzIG1hcHBpbmcuCiAgICAgICAgICAgIHVsb2coYE15dGhpYyBKSVQ6IG1hcCBwYWdlIHplcm8sIFRFQj0weCR7eDAudG9TdHJpbmcoMTYpfSBzaXplPTB4JHt4MS50b1N0cmluZygxNil9YCk7CgogICAgICAgICAgICBsZXQgc3VjY2VzcyA9IDBuOwoKICAgICAgICAgICAgLy8gVHJ5IGFsbG9jYXRpbmcgUlcgbWVtb3J5IGF0IGFkZHJlc3MgMCB2aWEgX00gd2l0aCBmaXhlZCBhZGRyZXNzCiAgICAgICAgICAgIC8vIFN0aWtEZWJ1ZydzIF9NIGNvbW1hbmQ6IF9NPHNpemU+LDxwZXJtcz4g4oCUIGJ1dCBkb2Vzbid0IHN1cHBvcnQgZml4ZWQgYWRkcgogICAgICAgICAgICAvLyBUcnkgR0RCIG1lbW9yeSBhbGxvY2F0aW9uOiBtbWFwIHZpYSB0aGUgZGVidWdnZXIncyB0YXNrIHBvcnQKICAgICAgICAgICAgLy8gVXNlIHZDb250IG9yIGRpcmVjdCBNYWNoIGNhbGxzIGlmIGF2YWlsYWJsZQoKICAgICAgICAgICAgLy8gQXBwcm9hY2ggMTogVHJ5IHdyaXRpbmcgVEVCIGRhdGEgdG8gYWRkcmVzcyAwIGRpcmVjdGx5LgogICAgICAgICAgICAvLyBJZiB0aGUgaGFyZHdhcmUgemVybyBwYWdlIGlzIHdyaXRhYmxlIHZpYSB0aGUgZGVidWdnZXIsIHRoaXMgd29ya3MuCiAgICAgICAgICAgIGlmICh4MCAhPT0gMG4gJiYgeDEgIT09IDBuKSB7CiAgICAgICAgICAgICAgICAvLyBSZWFkIFRFQiBkYXRhIGZyb20gdGhlIGFwcCdzIG1lbW9yeQogICAgICAgICAgICAgICAgbGV0IHRlYlBhZ2UgPSB4MCAmIH4weDNGRkZuOyAgLy8gYWxpZ24gdG8gMTZLQiBwYWdlCiAgICAgICAgICAgICAgICBsZXQgdGViT2ZmID0geDAgLSB0ZWJQYWdlOwoKICAgICAgICAgICAgICAgIC8vIFRyeSB0byB3cml0ZSBURUIgZGF0YSBhdCBhZGRyZXNzIDAgdmlhIEdEQiBNIGNvbW1hbmQKICAgICAgICAgICAgICAgIC8vIFJlYWQgMjU2IGJ5dGVzIGZyb20gVEVCIChlbm91Z2ggZm9yIFBFQiBwb2ludGVyIGF0IG9mZnNldCAweDYwKQogICAgICAgICAgICAgICAgbGV0IHRlYkRhdGEgPSBzZW5kX2NvbW1hbmQoYG0ke3gwLnRvU3RyaW5nKDE2KX0sMTAwYCk7CiAgICAgICAgICAgICAgICBpZiAodGViRGF0YSAmJiB0ZWJEYXRhLmxlbmd0aCA+IDApIHsKICAgICAgICAgICAgICAgICAgICAvLyBXcml0ZSBpdCB0byBhZGRyZXNzIDArdGViT2ZmCiAgICAgICAgICAgICAgICAgICAgbGV0IHdyaXRlUmVzcCA9IHNlbmRfY29tbWFuZChgTSR7dGViT2ZmLnRvU3RyaW5nKDE2KX0sJHsodGViRGF0YS5sZW5ndGgvMikudG9TdHJpbmcoMTYpfToke3RlYkRhdGF9YCk7CiAgICAgICAgICAgICAgICAgICAgdWxvZyhgTXl0aGljIEpJVDogd3JpdGUgVEVCIHRvIHBhZ2UwIG9mZnNldCAweCR7dGViT2ZmLnRvU3RyaW5nKDE2KX06ICR7d3JpdGVSZXNwfWApOwogICAgICAgICAgICAgICAgICAgIGlmICh3cml0ZVJlc3AgPT09ICdPSycpIHsKICAgICAgICAgICAgICAgICAgICAgICAgc3VjY2VzcyA9IDFuOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQoKICAgICAgICAgICAgc2VuZF9jb21tYW5kKGBQMD0ke251bWJlclRvTGl0dGxlRW5kaWFuSGV4U3RyaW5nKHN1Y2Nlc3MpfTt0aHJlYWQ6JHt0aWR9O2ApOwogICAgICAgIH0KCiAgICB9IGVsc2UgaWYgKGJya0ltbSA9PT0gMHg2OSkgewogICAgICAgIC8vIExlZ2FjeSBwcm90b2NvbAogICAgICAgIHVsb2coYE15dGhpYyBKSVQ6IGxlZ2FjeSBCUksgMHg2OSwgeDA9MHgke3gwLnRvU3RyaW5nKDE2KX1gKTsKICAgICAgICBpZiAoeDAgIT09IDBuKSB7CiAgICAgICAgICAgIHByZXBhcmVfbWVtb3J5X3JlZ2lvbih4MCwgeDApOwogICAgICAgIH0KICAgICAgICBzZW5kX2NvbW1hbmQoYFAwPSR7bnVtYmVyVG9MaXR0bGVFbmRpYW5IZXhTdHJpbmcoeDApfTt0aHJlYWQ6JHt0aWR9O2ApOwogICAgfQp9Cg=="

    /// Load script from mythic-jit.js file next to the binary (development convenience).
    /// Falls back to the embedded base64 above for release builds.
    private static var resolvedScriptBase64: String {
        // Try loading from bundle first (if added to Copy Bundle Resources)
        if let url = Bundle.main.url(forResource: "mythic-jit", withExtension: "js"),
           let data = try? Data(contentsOf: url) {
            return data.base64EncodedString()
        }
        return scriptBase64
    }

    /// Check if StikDebug or StikJIT is available by trying to open their URL.
    static var isAvailable: Bool {
        guard let url = URL(string: "stikjit://enable-jit") else { return false }
        return UIApplication.shared.canOpenURL(url)
    }

    /// Open StikDebug with our JIT script embedded in the URL.
    /// StikDebug will attach to our process and run the script.
    static func enableJIT(completion: @escaping (Bool) -> Void) {
        let bundleId = Bundle.main.bundleIdentifier ?? "com.mythic.emulator"

        // Build the URL with script data
        let scriptData = resolvedScriptBase64.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        let urlString = "stikjit://enable-jit?bundle-id=\(bundleId)&script-data=\(scriptData)"

        guard let url = URL(string: urlString) else {
            LogStore.shared.log("Failed to build StikJIT URL", level: .error)
            completion(false)
            return
        }

        LogStore.shared.log("Opening StikDebug to enable JIT...")

        UIApplication.shared.open(url, options: [:]) { success in
            if !success {
                LogStore.shared.log("Failed to open StikDebug. Is it installed?", level: .error)
                completion(false)
                return
            }

            // Poll for CS_DEBUGGED flag
            pollForJIT(completion: completion)
        }
    }

    /// Poll every 0.5s until CS_DEBUGGED is set, then call completion.
    private static func pollForJIT(completion: @escaping (Bool) -> Void) {
        Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { timer in
            if jit_check_debugged() {
                timer.invalidate()
                LogStore.shared.log("JIT enabled! (CS_DEBUGGED set)", level: .success)
                completion(true)
            }
        }
    }

    /// Allocate a JIT memory pool via BRK #0xf00d, then detach the debugger.
    /// Call this after CS_DEBUGGED is confirmed.
    /// Returns the allocated RX base address and RW mapping, or nil on failure.
    static func allocateAndDetach(poolSize: Int = 128 * 1024 * 1024) -> (rx: UnsafeMutableRawPointer, rw: UnsafeMutableRawPointer, size: Int)? {
        guard let result = allocatePool(poolSize: poolSize) else { return nil }
        // Don't detach yet — Wine needs the debugger to prepare PE DLL code pages.
        // Detach will happen later via detachDebugger().
        return result
    }

    /// Allocate a JIT memory pool via BRK #0xf00d WITHOUT detaching the debugger.
    /// The debugger stays attached so Wine can use BRK to prepare PE code pages.
    static func allocatePool(poolSize: Int = 128 * 1024 * 1024) -> (rx: UnsafeMutableRawPointer, rw: UnsafeMutableRawPointer, size: Int)? {
        LogStore.shared.log("Allocating \(poolSize / 1024 / 1024)MB JIT pool via debugger...")

        // iOS-Mythic: FEX's dispatcher emit has a position-dependent encoding
        // bug — only works when the JIT pool lands at a high enough address
        // (empirically ≥ 0x119000000, so dispatcher at +0x7ffc130 has top byte
        // 0x12). When iOS allocates 0x114-0x117xxx the dispatcher's literal-
        // pool fixups silently break and execution branches to zero memory
        // before the first compiled block runs. Pre-claim ~96MB of low address
        // space to push the next ANYWHERE allocation up.
        //
        // We keep these allocations alive for the lifetime of the process —
        // freeing them could let iOS reuse them and cause aliasing issues.
        var pinChunks: [vm_address_t] = []
        let chunkSize = 16 * 1024 * 1024  // 16 MB per chunk
        // Pin until the allocation frontier crosses the mode-A threshold
        // (0x119000000) instead of a fixed 96MB. A fixed count loses the
        // ASLR lottery whenever the base slide is low (observed 2026-07-03:
        // 6 chunks ended at 0x118790000, pool landed 8.4MB short of the
        // threshold and the run fast-failed). vm_allocate is zero-fill
        // reserve-only, so extra chunks don't add resident footprint.
        // The BAD POOL check below stays as the safety net for non-
        // sequential placements.
        let pinTarget: vm_address_t = 0x119000000
        let maxChunks = 32                 // safety cap (512 MB of reservation)
        for i in 0..<maxChunks {
            var addr: vm_address_t = 0
            let kr = vm_allocate(mach_task_self_, &addr, vm_size_t(chunkSize), VM_FLAGS_ANYWHERE)
            if kr == KERN_SUCCESS {
                pinChunks.append(addr)
                LogStore.shared.log(String(format: "JIT-pool pin chunk %d at 0x%lx (16MB)", i, Int(addr)))
                if addr + vm_address_t(chunkSize) >= pinTarget { break }
            } else {
                LogStore.shared.log("JIT-pool pin chunk \(i) FAILED kr=\(kr)", level: .error)
                break
            }
        }

        // Ask debugger to allocate RX pages (x0=0 triggers _M allocation).
        // With pin chunks claimed, this should land at a higher address.
        //
        // Two placement constraints (violating either bricks the session):
        // - LOW BOUND: FEX has a position-dependent emit bug below
        //   0x119000000 (mode A: dispatcher branches to zero memory before
        //   block 0 runs; higher-address mode B is runtime-patched in
        //   signal_arm64_ios.c init_syscall_frame).
        // - GUEST WINDOW (ml78, 2026-07-13): with the 896MB pool the kernel
        //   often places the region at 0x7000000000 — inside the guest
        //   x86-64 64GB window [0x70,0x80)G where Wine packs PE images and
        //   the fault handlers classify PCs as guest addresses. Executing
        //   pool code there hangs the first pool call silently (black
        //   screen / wallpaper-only desktop).
        // Reject bad placements and re-roll: a bad region is freed when the
        // kernel allows, otherwise kept alive as a pin — either way the next
        // jit26 pick must land elsewhere.
        let goodLow = 0x119000000
        let guestLo = 0x7000000000
        let guestHi = 0x8000000000
        var rxPtrOpt: UnsafeMutableRawPointer? = nil
        for attempt in 0..<3 {
            guard let p = jit26_prepare_region(nil, poolSize), p != UnsafeMutableRawPointer(bitPattern: 0) else {
                LogStore.shared.log("Debugger failed to allocate RX memory (attempt \(attempt))", level: .error)
                break
            }
            let a = Int(bitPattern: p)
            let inGuestWindow = a + poolSize > guestLo && a < guestHi
            if a >= goodLow && !inGuestWindow {
                rxPtrOpt = p
                break
            }
            LogStore.shared.log(String(format: "BAD POOL placement 0x%lx (%@) — re-rolling (attempt %d)",
                                       a, a < goodLow ? "mode A low" : "guest 64G window",
                                       attempt), level: .error)
            let dkr = vm_deallocate(mach_task_self_, vm_address_t(a), vm_size_t(poolSize))
            LogStore.shared.log(dkr == KERN_SUCCESS
                ? "  bad region freed"
                : "  bad region kept as pin (vm_deallocate kr=\(dkr))")
        }
        guard let rxPtr = rxPtrOpt else {
            LogStore.shared.log("BAD POOL: no valid placement after retries. Killing in 10s — please relaunch.", level: .error)
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 10) {
                LogStore.shared.log("BAD POOL — exiting now. Relaunch the app.", level: .error)
                exit(0)
            }
            return nil
        }
        let rxAddr = Int(bitPattern: rxPtr)
        LogStore.shared.log("RX pool at \(String(format: "%p", rxAddr))")

        // Create RW mapping via vm_remap
        var rwAddr: vm_address_t = 0
        var curProt: vm_prot_t = 0
        var maxProt: vm_prot_t = 0

        // task #35: place the RW alias BELOW the 64GB carveout floor.
        // With VM_FLAGS_ANYWHERE the kernel picks the first free address above
        // the GPU carveout [64G,448G) — which is 0x7000000000 exactly. That is
        // the base of a 16GB jumbo slot, so this 896MB data-only mapping was
        // sterilizing a whole slot that CEF's PartitionAlloc needs. The top
        // window [448G,512G) holds only four such slots and CEF wants at least
        // four pools, so we cannot afford to spend one on ourselves.
        // Data-only (never executed — exec always goes through the RX alias),
        // so placement is unconstrained; fall back to ANYWHERE if all candidates
        // are taken, which restores the previous behaviour exactly.
        // ml91: six hand-picked candidates (8/12/16/24/32/48G) ALL failed —
        // sub-64G is far more crowded than assumed. Sweep the whole region on a
        // 1GB stride instead of guessing. Each failed vm_remap(FIXED) is cheap,
        // so ~58 probes at startup costs nothing and finds any real hole.
        // ml92 measured the real map: there is NO sub-64G space at all. The only
        // "free" region down there (0..0x102454000) is __PAGEZERO, and 4G-64G is
        // fully reserved (malloc xzone) — 58 probes on a 1GB stride found nothing.
        // Usable VA is exactly one ~63GB window, 0x7038000000..0x7fffdf0000.
        //
        // That window holds four 16GB-aligned slots (448/464/480/496G) and CEF's
        // PartitionAlloc wants one pool per slot. Landing here at 0x7000000000
        // spends the 448G slot on an 896MB mapping. Slot 496G is ALREADY ruined
        // by Wine furniture (PE images at ~0x7e874c0000 = 505.8G), so parking at
        // the very top costs nothing that isn't already lost and hands 448G back
        // to PartitionAlloc intact.
        // ml91/ml92/ml93: relocating this alias was tried and REVERTED. The map
        // says usable VA is a single ~63GB window (0x7038000000..0x7fffdf0000);
        // sub-64G is __PAGEZERO plus a fully-reserved 4G-64G band, so 58 probes
        // on a 1GB stride found nothing (ml92). Parking at the top of space
        // instead (0x7fc8000000) DID place, but Wine allocates its furniture
        // top-down — the TEB landed 1.25MB below us at 0x7fc7ec0000, pool copies
        // came out zero-filled, and libarm64ecfex died on 8 exec faults before
        // CEF was even reached (ml93). There is nowhere to put an 896MB mapping
        // that does not cost either a 16GB PartitionAlloc slot or Wine's own
        // furniture. The kernel pick (0x7000000000, base of the window) is the
        // least harmful: it spends the 448G slot but leaves the top — where Wine
        // clusters — alone.
        // ml96 census: CEF needs THREE 16GB pools (48GB), not the 144GB a naive
        // sum suggested — #3/#4/#5 are one pool re-rolling its hint, and the two
        // 32GB requests are that same pool over-reserving for 16GB ALIGNMENT.
        // 48GB fits in the 63GB window, so the third pool fails only because no
        // 16GB-ALIGNED slot is left: 464G and 480G are taken, 496G is broken by
        // Wine furniture, and 448G is spent on this 896MB alias.
        //
        // Freeing 448G should let pool 3 land. ml93 tried that and failed by
        // parking at 0x7fc8000000 — the extreme top, exactly where Wine
        // allocates its furniture top-down (the TEB landed 1.25MB below us and
        // pool copies came back zeroed). The map says 0x7c00000000..0x7e874c0000
        // is free, so take the BOTTOM of the already-broken 496G slot instead
        // and leave the top for Wine.
        // DO NOT relocate this alias without new evidence. Three placements were
        // measured against the default kernel pick (0x7000000000, which the
        // kernel picks because it is the first free address above the GPU
        // carveout):
        //   0x7000000000 (default)  ml94=8, ml96=1  exec faults, reaches libcef
        //   0x7fc8000000 (top)      ml93=8          exec faults, dies before CEF
        //   0x7c00000000 (496G)     ml97=16, ml98=16 exec faults, dies before CEF
        // Same fault class in every case (pool page loses content/exec, on a
        // recycled range) — relocation makes an EXISTING intermittent bug worse
        // rather than introducing a new one. Two mechanisms were proposed and
        // BOTH disproven: Wine furniture collision (ml93) and the reclaim-recover
        // band claiming the alias (ml97; the band exclusion landed in
        // signal_arm64_ios.c and did NOT change the count). Whatever couples the
        // alias base to pool stability is still unidentified.
        //
        // Cost of staying here: the alias occupies the base of the 448G slot, so
        // PartitionAlloc gets only two of the three 16GB-aligned pools it needs
        // (see the ml96 [jumbo#N] census). Freeing that slot is worth doing —
        // but by moving WINE's furniture out of 496G, not by moving this.
        rwAddr = 0
        let kr1 = vm_remap(
            mach_task_self_,
            &rwAddr,
            vm_size_t(poolSize),
            0,
            VM_FLAGS_ANYWHERE,
            mach_task_self_,
            vm_address_t(bitPattern: rxPtr),
            0, // copy = false
            &curProt,
            &maxProt,
            VM_INHERIT_NONE
        )

        guard kr1 == KERN_SUCCESS else {
            LogStore.shared.log("vm_remap failed: \(kr1)", level: .error)
            return nil
        }

        // Set RW protection
        let kr2 = vm_protect(mach_task_self_, rwAddr, vm_size_t(poolSize), 0, VM_PROT_READ | VM_PROT_WRITE)
        guard kr2 == KERN_SUCCESS else {
            LogStore.shared.log("vm_protect(RW) failed: \(kr2)", level: .error)
            vm_deallocate(mach_task_self_, rwAddr, vm_size_t(poolSize))
            return nil
        }

        let rwPtr = UnsafeMutableRawPointer(bitPattern: rwAddr)!
        LogStore.shared.log("RW mapping at \(String(format: "%p", Int(bitPattern: rwPtr)))")
        LogStore.shared.log("JIT pool ready (debugger still attached).", level: .success)

        return (rx: rxPtr, rw: rwPtr, size: poolSize)
    }

    /// Detach the debugger. Call this after Wine is done loading PE DLLs.
    static func detachDebugger() {
        LogStore.shared.log("Detaching debugger...")
        jit26_detach()
        // task #34: signal in-process waiters (share-probe poller). CS_DEBUGGED
        // is sticky post-detach, so an env flag is the reliable signal.
        setenv("MYTHIC_DETACHED", "1", 1)
        LogStore.shared.log("Debugger detached.", level: .success)
    }
}

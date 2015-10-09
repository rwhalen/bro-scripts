module ExtractFiles;

export {
	const extract_file_types: set[string] = [
		"application/x-dosexec",
		"application/x-executable"
	] &redef;
}

event file_sniff(f: fa_file, meta: fa_metadata) {
	
	#Check MIME Type for File Record
	if (meta?$mime_type) {
		#Look for MIME Types that we want to extract for analysis
		if (meta$mime_type in extract_file_types) {
			local ftype = meta$mime_type;
			local fuid = f$id;
			local fsource = f$source;
			local fname = fmt("extract-%s-%s", fsource, fuid);
			print fmt("*** Found %s in %s.  Saved as %s.  File ID is %s", ftype, fsource, fname, fuid);
			Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
		}
	}
}
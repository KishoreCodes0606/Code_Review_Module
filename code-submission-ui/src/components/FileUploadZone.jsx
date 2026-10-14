import React, { useState, useRef } from 'react';
import { UploadCloud, FileCode2, AlertCircle, CheckCircle, X, ArrowUpRight } from 'lucide-react';

export default function FileUploadZone({
  uploadedFile,
  onFileLoaded,
  onRemoveFile
}) {
  const [isDragging, setIsDragging] = useState(false);
  const [fileError, setFileError] = useState(null);
  const fileInputRef = useRef(null);

  const processFile = (file) => {
    setFileError(null);

    if (!file) return;

    // Check extension
    const ext = file.name.split('.').pop().toLowerCase();
    const binaryExts = ['exe', 'dll', 'so', 'bin', 'zip', 'tar', 'gz', 'png', 'jpg', 'pdf', 'docx'];
    if (binaryExts.includes(ext)) {
      setFileError(`Cannot inspect binary file (.${ext}). Please upload a source code file.`);
      return;
    }

    // Check size limit: 200 KB
    const maxBytes = 200 * 1024;
    if (file.size > maxBytes) {
      setFileError(`File size (${(file.size / 1024).toFixed(1)} KB) exceeds the 200 KB submission limit.`);
      return;
    }

    // Read file as UTF-8 text
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      onFileLoaded({
        name: file.name,
        size: file.size,
        extension: ext,
        content: content,
        lastModified: file.lastModified
      });
    };
    reader.onerror = () => {
      setFileError('Failed to read the file. Please ensure it is a valid UTF-8 text file.');
    };
    reader.readAsText(file);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      processFile(file);
    }
  };

  const handleFileInputChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      processFile(file);
    }
  };

  return (
    <div className="space-y-3">
      {!uploadedFile ? (
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
            isDragging
              ? 'border-indigo-500 bg-indigo-500/10 scale-[1.005]'
              : 'border-slate-700/80 hover:border-slate-600 bg-slate-900/40 hover:bg-slate-900/70'
          }`}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileInputChange}
            accept=".py,.java,.js,.ts,.cpp,.c,.cs,.php,.html,.css,.txt"
            className="hidden"
          />

          <div className="flex flex-col items-center justify-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <UploadCloud className="w-6 h-6" />
            </div>

            <div>
              <p className="text-sm font-medium text-slate-200">
                Click to browse or drag and drop your source file
              </p>
              <p className="text-xs text-slate-400 mt-1">
                Accepted: Python (<code className="text-yellow-400 font-mono">.py</code>) and Java (<code className="text-orange-400 font-mono">.java</code>) up to 200 KB
              </p>
            </div>

            <div className="flex items-center gap-2 mt-2">
              <span className="text-[11px] px-2.5 py-1 rounded bg-yellow-500/10 text-yellow-300 border border-yellow-500/20 font-mono">
                Python (.py)
              </span>
              <span className="text-[11px] px-2.5 py-1 rounded bg-orange-500/10 text-orange-300 border border-orange-500/20 font-mono">
                Java (.java)
              </span>
              <span className="text-[11px] text-slate-500">Other languages rejected</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="flex items-center justify-between p-4 bg-slate-900/80 rounded-xl border border-indigo-500/30 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <FileCode2 className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-white font-mono">
                  {uploadedFile.name}
                </span>
                <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300">
                  {uploadedFile.extension}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {(uploadedFile.size / 1024).toFixed(2)} KB · Loaded & synced to code editor
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
            >
              Replace
            </button>
            <button
              type="button"
              onClick={onRemoveFile}
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
              title="Remove file"
            >
              <X className="w-4 h-4" />
            </button>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileInputChange}
              accept=".py,.java"
              className="hidden"
            />
          </div>
        </div>
      )}

      {fileError && (
        <div className="flex items-start gap-2.5 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
          <AlertCircle className="w-4 h-4 mt-0.5 shrink-0 text-rose-400" />
          <span>{fileError}</span>
        </div>
      )}
    </div>
  );
}

using System;

namespace PwSafeLib.Filesystem
{
    /// <summary>
    /// Password Safe File Header
    /// </summary>
    public class PwsFileHeader
    {
        /// <summary>
        /// Unique Identifier of the password safe.
        /// </summary>
        public Guid Uuid { get; set; }

        /// <summary>
        /// Password Safe File Version.
        /// </summary>
        public Version Version { get; set; }

        /// <summary>
        /// User Preferences.
        /// </summary>
        public string PrefString { get; set; }

        /// <summary>
        /// Date when the safe was last saved.
        /// </summary>
        public DateTime WhenLastSaved { get; set; }

        /// <summary>
        /// The username of the user who last saved the file.
        /// </summary>
        public string LastSavedBy { get; set; }

        /// <summary>
        /// The hostname of the device that last wrote to the file.
        /// </summary>
        public string LastSavedOn { get; set; }

        /// <summary>
        /// Name of the application that last modified the file.
        /// </summary>
        public string WhatLastSaved { get; set; }

        /// <summary>
        /// Name of the password safe.
        /// </summary>
        public string DbName { get; set; }

        /// <summary>
        /// A description of the safe.
        /// </summary>
        public string DbDescription { get; set; }
    }
}

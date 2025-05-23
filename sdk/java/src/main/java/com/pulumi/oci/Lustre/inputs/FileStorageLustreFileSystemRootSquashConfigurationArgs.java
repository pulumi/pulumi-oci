// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Lustre.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FileStorageLustreFileSystemRootSquashConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final FileStorageLustreFileSystemRootSquashConfigurationArgs Empty = new FileStorageLustreFileSystemRootSquashConfigurationArgs();

    /**
     * (Updatable) A list of NIDs allowed with this lustre file system not to be squashed. A maximum of 10 is allowed.
     * 
     */
    @Import(name="clientExceptions")
    private @Nullable Output<List<String>> clientExceptions;

    /**
     * @return (Updatable) A list of NIDs allowed with this lustre file system not to be squashed. A maximum of 10 is allowed.
     * 
     */
    public Optional<Output<List<String>>> clientExceptions() {
        return Optional.ofNullable(this.clientExceptions);
    }

    /**
     * (Updatable) Used when clients accessing the Lustre file system have their UID and GID remapped to `squashUid` and `squashGid`. If `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `NONE`.
     * 
     */
    @Import(name="identitySquash")
    private @Nullable Output<String> identitySquash;

    /**
     * @return (Updatable) Used when clients accessing the Lustre file system have their UID and GID remapped to `squashUid` and `squashGid`. If `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `NONE`.
     * 
     */
    public Optional<Output<String>> identitySquash() {
        return Optional.ofNullable(this.identitySquash);
    }

    /**
     * (Updatable) The GID value to remap to when squashing a client GID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
     * 
     */
    @Import(name="squashGid")
    private @Nullable Output<String> squashGid;

    /**
     * @return (Updatable) The GID value to remap to when squashing a client GID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
     * 
     */
    public Optional<Output<String>> squashGid() {
        return Optional.ofNullable(this.squashGid);
    }

    /**
     * (Updatable) The UID value to remap to when squashing a client UID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
     * 
     */
    @Import(name="squashUid")
    private @Nullable Output<String> squashUid;

    /**
     * @return (Updatable) The UID value to remap to when squashing a client UID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
     * 
     */
    public Optional<Output<String>> squashUid() {
        return Optional.ofNullable(this.squashUid);
    }

    private FileStorageLustreFileSystemRootSquashConfigurationArgs() {}

    private FileStorageLustreFileSystemRootSquashConfigurationArgs(FileStorageLustreFileSystemRootSquashConfigurationArgs $) {
        this.clientExceptions = $.clientExceptions;
        this.identitySquash = $.identitySquash;
        this.squashGid = $.squashGid;
        this.squashUid = $.squashUid;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FileStorageLustreFileSystemRootSquashConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FileStorageLustreFileSystemRootSquashConfigurationArgs $;

        public Builder() {
            $ = new FileStorageLustreFileSystemRootSquashConfigurationArgs();
        }

        public Builder(FileStorageLustreFileSystemRootSquashConfigurationArgs defaults) {
            $ = new FileStorageLustreFileSystemRootSquashConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param clientExceptions (Updatable) A list of NIDs allowed with this lustre file system not to be squashed. A maximum of 10 is allowed.
         * 
         * @return builder
         * 
         */
        public Builder clientExceptions(@Nullable Output<List<String>> clientExceptions) {
            $.clientExceptions = clientExceptions;
            return this;
        }

        /**
         * @param clientExceptions (Updatable) A list of NIDs allowed with this lustre file system not to be squashed. A maximum of 10 is allowed.
         * 
         * @return builder
         * 
         */
        public Builder clientExceptions(List<String> clientExceptions) {
            return clientExceptions(Output.of(clientExceptions));
        }

        /**
         * @param clientExceptions (Updatable) A list of NIDs allowed with this lustre file system not to be squashed. A maximum of 10 is allowed.
         * 
         * @return builder
         * 
         */
        public Builder clientExceptions(String... clientExceptions) {
            return clientExceptions(List.of(clientExceptions));
        }

        /**
         * @param identitySquash (Updatable) Used when clients accessing the Lustre file system have their UID and GID remapped to `squashUid` and `squashGid`. If `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `NONE`.
         * 
         * @return builder
         * 
         */
        public Builder identitySquash(@Nullable Output<String> identitySquash) {
            $.identitySquash = identitySquash;
            return this;
        }

        /**
         * @param identitySquash (Updatable) Used when clients accessing the Lustre file system have their UID and GID remapped to `squashUid` and `squashGid`. If `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `NONE`.
         * 
         * @return builder
         * 
         */
        public Builder identitySquash(String identitySquash) {
            return identitySquash(Output.of(identitySquash));
        }

        /**
         * @param squashGid (Updatable) The GID value to remap to when squashing a client GID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
         * 
         * @return builder
         * 
         */
        public Builder squashGid(@Nullable Output<String> squashGid) {
            $.squashGid = squashGid;
            return this;
        }

        /**
         * @param squashGid (Updatable) The GID value to remap to when squashing a client GID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
         * 
         * @return builder
         * 
         */
        public Builder squashGid(String squashGid) {
            return squashGid(Output.of(squashGid));
        }

        /**
         * @param squashUid (Updatable) The UID value to remap to when squashing a client UID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
         * 
         * @return builder
         * 
         */
        public Builder squashUid(@Nullable Output<String> squashUid) {
            $.squashUid = squashUid;
            return this;
        }

        /**
         * @param squashUid (Updatable) The UID value to remap to when squashing a client UID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
         * 
         * @return builder
         * 
         */
        public Builder squashUid(String squashUid) {
            return squashUid(Output.of(squashUid));
        }

        public FileStorageLustreFileSystemRootSquashConfigurationArgs build() {
            return $;
        }
    }

}

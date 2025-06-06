// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Lustre.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetFileStorageLustreFileSystemRootSquashConfiguration {
    /**
     * @return A list of NIDs allowed with this lustre file system not to be squashed. A maximum of 10 is allowed.
     * 
     */
    private List<String> clientExceptions;
    /**
     * @return Used when clients accessing the Lustre file system have their UID and GID remapped to `squashUid` and `squashGid`. If `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `NONE`.
     * 
     */
    private String identitySquash;
    /**
     * @return The GID value to remap to when squashing a client GID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
     * 
     */
    private String squashGid;
    /**
     * @return The UID value to remap to when squashing a client UID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
     * 
     */
    private String squashUid;

    private GetFileStorageLustreFileSystemRootSquashConfiguration() {}
    /**
     * @return A list of NIDs allowed with this lustre file system not to be squashed. A maximum of 10 is allowed.
     * 
     */
    public List<String> clientExceptions() {
        return this.clientExceptions;
    }
    /**
     * @return Used when clients accessing the Lustre file system have their UID and GID remapped to `squashUid` and `squashGid`. If `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `NONE`.
     * 
     */
    public String identitySquash() {
        return this.identitySquash;
    }
    /**
     * @return The GID value to remap to when squashing a client GID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
     * 
     */
    public String squashGid() {
        return this.squashGid;
    }
    /**
     * @return The UID value to remap to when squashing a client UID. See `identitySquash` for more details. If unspecified, defaults to `65534`.
     * 
     */
    public String squashUid() {
        return this.squashUid;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFileStorageLustreFileSystemRootSquashConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> clientExceptions;
        private String identitySquash;
        private String squashGid;
        private String squashUid;
        public Builder() {}
        public Builder(GetFileStorageLustreFileSystemRootSquashConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.clientExceptions = defaults.clientExceptions;
    	      this.identitySquash = defaults.identitySquash;
    	      this.squashGid = defaults.squashGid;
    	      this.squashUid = defaults.squashUid;
        }

        @CustomType.Setter
        public Builder clientExceptions(List<String> clientExceptions) {
            if (clientExceptions == null) {
              throw new MissingRequiredPropertyException("GetFileStorageLustreFileSystemRootSquashConfiguration", "clientExceptions");
            }
            this.clientExceptions = clientExceptions;
            return this;
        }
        public Builder clientExceptions(String... clientExceptions) {
            return clientExceptions(List.of(clientExceptions));
        }
        @CustomType.Setter
        public Builder identitySquash(String identitySquash) {
            if (identitySquash == null) {
              throw new MissingRequiredPropertyException("GetFileStorageLustreFileSystemRootSquashConfiguration", "identitySquash");
            }
            this.identitySquash = identitySquash;
            return this;
        }
        @CustomType.Setter
        public Builder squashGid(String squashGid) {
            if (squashGid == null) {
              throw new MissingRequiredPropertyException("GetFileStorageLustreFileSystemRootSquashConfiguration", "squashGid");
            }
            this.squashGid = squashGid;
            return this;
        }
        @CustomType.Setter
        public Builder squashUid(String squashUid) {
            if (squashUid == null) {
              throw new MissingRequiredPropertyException("GetFileStorageLustreFileSystemRootSquashConfiguration", "squashUid");
            }
            this.squashUid = squashUid;
            return this;
        }
        public GetFileStorageLustreFileSystemRootSquashConfiguration build() {
            final var _resultValue = new GetFileStorageLustreFileSystemRootSquashConfiguration();
            _resultValue.clientExceptions = clientExceptions;
            _resultValue.identitySquash = identitySquash;
            _resultValue.squashGid = squashGid;
            _resultValue.squashUid = squashUid;
            return _resultValue;
        }
    }
}

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExportSetsExportSet {
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
     * 
     */
    private String displayName;
    /**
     * @return Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
     * 
     */
    private String id;
    /**
     * @return Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be &#39;0&#39;.
     * 
     */
    private String maxFsStatBytes;
    /**
     * @return Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be &#39;0&#39;.
     * 
     */
    private String maxFsStatFiles;
    private String mountTargetId;
    /**
     * @return Filter results by the specified lifecycle state. Must be a valid state for the resource type.
     * 
     */
    private String state;
    /**
     * @return The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
     * 
     */
    private String vcnId;

    private GetExportSetsExportSet() {}
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be &#39;0&#39;.
     * 
     */
    public String maxFsStatBytes() {
        return this.maxFsStatBytes;
    }
    /**
     * @return Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be &#39;0&#39;.
     * 
     */
    public String maxFsStatFiles() {
        return this.maxFsStatFiles;
    }
    public String mountTargetId() {
        return this.mountTargetId;
    }
    /**
     * @return Filter results by the specified lifecycle state. Must be a valid state for the resource type.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
     * 
     */
    public String vcnId() {
        return this.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExportSetsExportSet defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String compartmentId;
        private String displayName;
        private String id;
        private String maxFsStatBytes;
        private String maxFsStatFiles;
        private String mountTargetId;
        private String state;
        private String timeCreated;
        private String vcnId;
        public Builder() {}
        public Builder(GetExportSetsExportSet defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.maxFsStatBytes = defaults.maxFsStatBytes;
    	      this.maxFsStatFiles = defaults.maxFsStatFiles;
    	      this.mountTargetId = defaults.mountTargetId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.vcnId = defaults.vcnId;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder maxFsStatBytes(String maxFsStatBytes) {
            this.maxFsStatBytes = Objects.requireNonNull(maxFsStatBytes);
            return this;
        }
        @CustomType.Setter
        public Builder maxFsStatFiles(String maxFsStatFiles) {
            this.maxFsStatFiles = Objects.requireNonNull(maxFsStatFiles);
            return this;
        }
        @CustomType.Setter
        public Builder mountTargetId(String mountTargetId) {
            this.mountTargetId = Objects.requireNonNull(mountTargetId);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder vcnId(String vcnId) {
            this.vcnId = Objects.requireNonNull(vcnId);
            return this;
        }
        public GetExportSetsExportSet build() {
            final var o = new GetExportSetsExportSet();
            o.availabilityDomain = availabilityDomain;
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.id = id;
            o.maxFsStatBytes = maxFsStatBytes;
            o.maxFsStatFiles = maxFsStatFiles;
            o.mountTargetId = mountTargetId;
            o.state = state;
            o.timeCreated = timeCreated;
            o.vcnId = vcnId;
            return o;
        }
    }
}
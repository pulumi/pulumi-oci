// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class BootVolumeSourceDetails {
    /**
     * @return The OCID of the boot volume replica.
     * 
     */
    private String id;
    /**
     * @return The type can be one of these values: `bootVolume`, `bootVolumeBackup`, `bootVolumeReplica`
     * 
     */
    private String type;

    private BootVolumeSourceDetails() {}
    /**
     * @return The OCID of the boot volume replica.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The type can be one of these values: `bootVolume`, `bootVolumeBackup`, `bootVolumeReplica`
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BootVolumeSourceDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private String type;
        public Builder() {}
        public Builder(BootVolumeSourceDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public BootVolumeSourceDetails build() {
            final var o = new BootVolumeSourceDetails();
            o.id = id;
            o.type = type;
            return o;
        }
    }
}
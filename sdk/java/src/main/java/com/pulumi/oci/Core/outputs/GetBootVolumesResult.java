// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetBootVolumesBootVolume;
import com.pulumi.oci.Core.outputs.GetBootVolumesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetBootVolumesResult {
    /**
     * @return The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private @Nullable String availabilityDomain;
    /**
     * @return The list of boot_volumes.
     * 
     */
    private List<GetBootVolumesBootVolume> bootVolumes;
    /**
     * @return The OCID of the compartment that contains the boot volume.
     * 
     */
    private @Nullable String compartmentId;
    private @Nullable List<GetBootVolumesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OCID of the source volume group.
     * 
     */
    private @Nullable String volumeGroupId;

    private GetBootVolumesResult() {}
    /**
     * @return The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    /**
     * @return The list of boot_volumes.
     * 
     */
    public List<GetBootVolumesBootVolume> bootVolumes() {
        return this.bootVolumes;
    }
    /**
     * @return The OCID of the compartment that contains the boot volume.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public List<GetBootVolumesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The OCID of the source volume group.
     * 
     */
    public Optional<String> volumeGroupId() {
        return Optional.ofNullable(this.volumeGroupId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBootVolumesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String availabilityDomain;
        private List<GetBootVolumesBootVolume> bootVolumes;
        private @Nullable String compartmentId;
        private @Nullable List<GetBootVolumesFilter> filters;
        private String id;
        private @Nullable String volumeGroupId;
        public Builder() {}
        public Builder(GetBootVolumesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.bootVolumes = defaults.bootVolumes;
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.volumeGroupId = defaults.volumeGroupId;
        }

        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder bootVolumes(List<GetBootVolumesBootVolume> bootVolumes) {
            this.bootVolumes = Objects.requireNonNull(bootVolumes);
            return this;
        }
        public Builder bootVolumes(GetBootVolumesBootVolume... bootVolumes) {
            return bootVolumes(List.of(bootVolumes));
        }
        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetBootVolumesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetBootVolumesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder volumeGroupId(@Nullable String volumeGroupId) {
            this.volumeGroupId = volumeGroupId;
            return this;
        }
        public GetBootVolumesResult build() {
            final var o = new GetBootVolumesResult();
            o.availabilityDomain = availabilityDomain;
            o.bootVolumes = bootVolumes;
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.volumeGroupId = volumeGroupId;
            return o;
        }
    }
}
// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetVolumeAttachmentsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVolumeAttachmentsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVolumeAttachmentsPlainArgs Empty = new GetVolumeAttachmentsPlainArgs();

    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable String availabilityDomain;

    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetVolumeAttachmentsFilter> filters;

    public Optional<List<GetVolumeAttachmentsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the instance.
     * 
     */
    @Import(name="instanceId")
    private @Nullable String instanceId;

    /**
     * @return The OCID of the instance.
     * 
     */
    public Optional<String> instanceId() {
        return Optional.ofNullable(this.instanceId);
    }

    /**
     * The OCID of the volume.
     * 
     */
    @Import(name="volumeId")
    private @Nullable String volumeId;

    /**
     * @return The OCID of the volume.
     * 
     */
    public Optional<String> volumeId() {
        return Optional.ofNullable(this.volumeId);
    }

    private GetVolumeAttachmentsPlainArgs() {}

    private GetVolumeAttachmentsPlainArgs(GetVolumeAttachmentsPlainArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.instanceId = $.instanceId;
        this.volumeId = $.volumeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVolumeAttachmentsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVolumeAttachmentsPlainArgs $;

        public Builder() {
            $ = new GetVolumeAttachmentsPlainArgs();
        }

        public Builder(GetVolumeAttachmentsPlainArgs defaults) {
            $ = new GetVolumeAttachmentsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the availability domain.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetVolumeAttachmentsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetVolumeAttachmentsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param instanceId The OCID of the instance.
         * 
         * @return builder
         * 
         */
        public Builder instanceId(@Nullable String instanceId) {
            $.instanceId = instanceId;
            return this;
        }

        /**
         * @param volumeId The OCID of the volume.
         * 
         * @return builder
         * 
         */
        public Builder volumeId(@Nullable String volumeId) {
            $.volumeId = volumeId;
            return this;
        }

        public GetVolumeAttachmentsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}
// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Oda.inputs.GetOdaPrivateEndpointAttachmentsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetOdaPrivateEndpointAttachmentsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOdaPrivateEndpointAttachmentsArgs Empty = new GetOdaPrivateEndpointAttachmentsArgs();

    /**
     * List the ODA Private Endpoint Attachments that belong to this compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return List the ODA Private Endpoint Attachments that belong to this compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetOdaPrivateEndpointAttachmentsFilterArgs>> filters;

    public Optional<Output<List<GetOdaPrivateEndpointAttachmentsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of ODA Private Endpoint.
     * 
     */
    @Import(name="odaPrivateEndpointId", required=true)
    private Output<String> odaPrivateEndpointId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of ODA Private Endpoint.
     * 
     */
    public Output<String> odaPrivateEndpointId() {
        return this.odaPrivateEndpointId;
    }

    /**
     * List only the ODA Private Endpoint Attachments that are in this lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return List only the ODA Private Endpoint Attachments that are in this lifecycle state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetOdaPrivateEndpointAttachmentsArgs() {}

    private GetOdaPrivateEndpointAttachmentsArgs(GetOdaPrivateEndpointAttachmentsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.odaPrivateEndpointId = $.odaPrivateEndpointId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOdaPrivateEndpointAttachmentsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOdaPrivateEndpointAttachmentsArgs $;

        public Builder() {
            $ = new GetOdaPrivateEndpointAttachmentsArgs();
        }

        public Builder(GetOdaPrivateEndpointAttachmentsArgs defaults) {
            $ = new GetOdaPrivateEndpointAttachmentsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId List the ODA Private Endpoint Attachments that belong to this compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId List the ODA Private Endpoint Attachments that belong to this compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetOdaPrivateEndpointAttachmentsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetOdaPrivateEndpointAttachmentsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetOdaPrivateEndpointAttachmentsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param odaPrivateEndpointId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of ODA Private Endpoint.
         * 
         * @return builder
         * 
         */
        public Builder odaPrivateEndpointId(Output<String> odaPrivateEndpointId) {
            $.odaPrivateEndpointId = odaPrivateEndpointId;
            return this;
        }

        /**
         * @param odaPrivateEndpointId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of ODA Private Endpoint.
         * 
         * @return builder
         * 
         */
        public Builder odaPrivateEndpointId(String odaPrivateEndpointId) {
            return odaPrivateEndpointId(Output.of(odaPrivateEndpointId));
        }

        /**
         * @param state List only the ODA Private Endpoint Attachments that are in this lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state List only the ODA Private Endpoint Attachments that are in this lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetOdaPrivateEndpointAttachmentsArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.odaPrivateEndpointId = Objects.requireNonNull($.odaPrivateEndpointId, "expected parameter 'odaPrivateEndpointId' to be non-null");
            return $;
        }
    }

}
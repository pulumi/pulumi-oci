// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetOperationsInsightsPrivateEndpointPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOperationsInsightsPrivateEndpointPlainArgs Empty = new GetOperationsInsightsPrivateEndpointPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Operation Insights private endpoint.
     * 
     */
    @Import(name="operationsInsightsPrivateEndpointId", required=true)
    private String operationsInsightsPrivateEndpointId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Operation Insights private endpoint.
     * 
     */
    public String operationsInsightsPrivateEndpointId() {
        return this.operationsInsightsPrivateEndpointId;
    }

    private GetOperationsInsightsPrivateEndpointPlainArgs() {}

    private GetOperationsInsightsPrivateEndpointPlainArgs(GetOperationsInsightsPrivateEndpointPlainArgs $) {
        this.operationsInsightsPrivateEndpointId = $.operationsInsightsPrivateEndpointId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOperationsInsightsPrivateEndpointPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOperationsInsightsPrivateEndpointPlainArgs $;

        public Builder() {
            $ = new GetOperationsInsightsPrivateEndpointPlainArgs();
        }

        public Builder(GetOperationsInsightsPrivateEndpointPlainArgs defaults) {
            $ = new GetOperationsInsightsPrivateEndpointPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param operationsInsightsPrivateEndpointId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Operation Insights private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder operationsInsightsPrivateEndpointId(String operationsInsightsPrivateEndpointId) {
            $.operationsInsightsPrivateEndpointId = operationsInsightsPrivateEndpointId;
            return this;
        }

        public GetOperationsInsightsPrivateEndpointPlainArgs build() {
            if ($.operationsInsightsPrivateEndpointId == null) {
                throw new MissingRequiredPropertyException("GetOperationsInsightsPrivateEndpointPlainArgs", "operationsInsightsPrivateEndpointId");
            }
            return $;
        }
    }

}

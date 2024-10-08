// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetPrivateEndpointArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPrivateEndpointArgs Empty = new GetPrivateEndpointArgs();

    /**
     * The unique ID for a Data Science private endpoint.
     * 
     */
    @Import(name="dataSciencePrivateEndpointId", required=true)
    private Output<String> dataSciencePrivateEndpointId;

    /**
     * @return The unique ID for a Data Science private endpoint.
     * 
     */
    public Output<String> dataSciencePrivateEndpointId() {
        return this.dataSciencePrivateEndpointId;
    }

    private GetPrivateEndpointArgs() {}

    private GetPrivateEndpointArgs(GetPrivateEndpointArgs $) {
        this.dataSciencePrivateEndpointId = $.dataSciencePrivateEndpointId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPrivateEndpointArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPrivateEndpointArgs $;

        public Builder() {
            $ = new GetPrivateEndpointArgs();
        }

        public Builder(GetPrivateEndpointArgs defaults) {
            $ = new GetPrivateEndpointArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dataSciencePrivateEndpointId The unique ID for a Data Science private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder dataSciencePrivateEndpointId(Output<String> dataSciencePrivateEndpointId) {
            $.dataSciencePrivateEndpointId = dataSciencePrivateEndpointId;
            return this;
        }

        /**
         * @param dataSciencePrivateEndpointId The unique ID for a Data Science private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder dataSciencePrivateEndpointId(String dataSciencePrivateEndpointId) {
            return dataSciencePrivateEndpointId(Output.of(dataSciencePrivateEndpointId));
        }

        public GetPrivateEndpointArgs build() {
            if ($.dataSciencePrivateEndpointId == null) {
                throw new MissingRequiredPropertyException("GetPrivateEndpointArgs", "dataSciencePrivateEndpointId");
            }
            return $;
        }
    }

}

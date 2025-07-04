// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetApiaccesscontrolPrivilegedApiRequestArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetApiaccesscontrolPrivilegedApiRequestArgs Empty = new GetApiaccesscontrolPrivilegedApiRequestArgs();

    /**
     * unique PrivilegedApiRequest identifier
     * 
     */
    @Import(name="privilegedApiRequestId", required=true)
    private Output<String> privilegedApiRequestId;

    /**
     * @return unique PrivilegedApiRequest identifier
     * 
     */
    public Output<String> privilegedApiRequestId() {
        return this.privilegedApiRequestId;
    }

    private GetApiaccesscontrolPrivilegedApiRequestArgs() {}

    private GetApiaccesscontrolPrivilegedApiRequestArgs(GetApiaccesscontrolPrivilegedApiRequestArgs $) {
        this.privilegedApiRequestId = $.privilegedApiRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetApiaccesscontrolPrivilegedApiRequestArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetApiaccesscontrolPrivilegedApiRequestArgs $;

        public Builder() {
            $ = new GetApiaccesscontrolPrivilegedApiRequestArgs();
        }

        public Builder(GetApiaccesscontrolPrivilegedApiRequestArgs defaults) {
            $ = new GetApiaccesscontrolPrivilegedApiRequestArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param privilegedApiRequestId unique PrivilegedApiRequest identifier
         * 
         * @return builder
         * 
         */
        public Builder privilegedApiRequestId(Output<String> privilegedApiRequestId) {
            $.privilegedApiRequestId = privilegedApiRequestId;
            return this;
        }

        /**
         * @param privilegedApiRequestId unique PrivilegedApiRequest identifier
         * 
         * @return builder
         * 
         */
        public Builder privilegedApiRequestId(String privilegedApiRequestId) {
            return privilegedApiRequestId(Output.of(privilegedApiRequestId));
        }

        public GetApiaccesscontrolPrivilegedApiRequestArgs build() {
            if ($.privilegedApiRequestId == null) {
                throw new MissingRequiredPropertyException("GetApiaccesscontrolPrivilegedApiRequestArgs", "privilegedApiRequestId");
            }
            return $;
        }
    }

}

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDomainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDomainArgs Empty = new GetDomainArgs();

    /**
     * The OCID of the domain
     * 
     */
    @Import(name="domainId", required=true)
    private Output<String> domainId;

    /**
     * @return The OCID of the domain
     * 
     */
    public Output<String> domainId() {
        return this.domainId;
    }

    private GetDomainArgs() {}

    private GetDomainArgs(GetDomainArgs $) {
        this.domainId = $.domainId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDomainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDomainArgs $;

        public Builder() {
            $ = new GetDomainArgs();
        }

        public Builder(GetDomainArgs defaults) {
            $ = new GetDomainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param domainId The OCID of the domain
         * 
         * @return builder
         * 
         */
        public Builder domainId(Output<String> domainId) {
            $.domainId = domainId;
            return this;
        }

        /**
         * @param domainId The OCID of the domain
         * 
         * @return builder
         * 
         */
        public Builder domainId(String domainId) {
            return domainId(Output.of(domainId));
        }

        public GetDomainArgs build() {
            if ($.domainId == null) {
                throw new MissingRequiredPropertyException("GetDomainArgs", "domainId");
            }
            return $;
        }
    }

}

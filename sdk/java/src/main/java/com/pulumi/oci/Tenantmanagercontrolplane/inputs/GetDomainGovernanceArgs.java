// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDomainGovernanceArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDomainGovernanceArgs Empty = new GetDomainGovernanceArgs();

    /**
     * The domain governance OCID.
     * 
     */
    @Import(name="domainGovernanceId", required=true)
    private Output<String> domainGovernanceId;

    /**
     * @return The domain governance OCID.
     * 
     */
    public Output<String> domainGovernanceId() {
        return this.domainGovernanceId;
    }

    private GetDomainGovernanceArgs() {}

    private GetDomainGovernanceArgs(GetDomainGovernanceArgs $) {
        this.domainGovernanceId = $.domainGovernanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDomainGovernanceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDomainGovernanceArgs $;

        public Builder() {
            $ = new GetDomainGovernanceArgs();
        }

        public Builder(GetDomainGovernanceArgs defaults) {
            $ = new GetDomainGovernanceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param domainGovernanceId The domain governance OCID.
         * 
         * @return builder
         * 
         */
        public Builder domainGovernanceId(Output<String> domainGovernanceId) {
            $.domainGovernanceId = domainGovernanceId;
            return this;
        }

        /**
         * @param domainGovernanceId The domain governance OCID.
         * 
         * @return builder
         * 
         */
        public Builder domainGovernanceId(String domainGovernanceId) {
            return domainGovernanceId(Output.of(domainGovernanceId));
        }

        public GetDomainGovernanceArgs build() {
            if ($.domainGovernanceId == null) {
                throw new MissingRequiredPropertyException("GetDomainGovernanceArgs", "domainGovernanceId");
            }
            return $;
        }
    }

}

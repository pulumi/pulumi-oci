// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LoadBalancer.inputs.GetCertificatesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetCertificatesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCertificatesArgs Empty = new GetCertificatesArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetCertificatesFilterArgs>> filters;

    public Optional<Output<List<GetCertificatesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the certificate bundles to be listed.
     * 
     */
    @Import(name="loadBalancerId", required=true)
    private Output<String> loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the certificate bundles to be listed.
     * 
     */
    public Output<String> loadBalancerId() {
        return this.loadBalancerId;
    }

    private GetCertificatesArgs() {}

    private GetCertificatesArgs(GetCertificatesArgs $) {
        this.filters = $.filters;
        this.loadBalancerId = $.loadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetCertificatesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCertificatesArgs $;

        public Builder() {
            $ = new GetCertificatesArgs();
        }

        public Builder(GetCertificatesArgs defaults) {
            $ = new GetCertificatesArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetCertificatesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetCertificatesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetCertificatesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the certificate bundles to be listed.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(Output<String> loadBalancerId) {
            $.loadBalancerId = loadBalancerId;
            return this;
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the certificate bundles to be listed.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(String loadBalancerId) {
            return loadBalancerId(Output.of(loadBalancerId));
        }

        public GetCertificatesArgs build() {
            if ($.loadBalancerId == null) {
                throw new MissingRequiredPropertyException("GetCertificatesArgs", "loadBalancerId");
            }
            return $;
        }
    }

}

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LoadBalancer.inputs.GetCertificatesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetCertificatesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCertificatesPlainArgs Empty = new GetCertificatesPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetCertificatesFilter> filters;

    public Optional<List<GetCertificatesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the certificate bundles to be listed.
     * 
     */
    @Import(name="loadBalancerId", required=true)
    private String loadBalancerId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the certificate bundles to be listed.
     * 
     */
    public String loadBalancerId() {
        return this.loadBalancerId;
    }

    private GetCertificatesPlainArgs() {}

    private GetCertificatesPlainArgs(GetCertificatesPlainArgs $) {
        this.filters = $.filters;
        this.loadBalancerId = $.loadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetCertificatesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCertificatesPlainArgs $;

        public Builder() {
            $ = new GetCertificatesPlainArgs();
        }

        public Builder(GetCertificatesPlainArgs defaults) {
            $ = new GetCertificatesPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetCertificatesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetCertificatesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param loadBalancerId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the certificate bundles to be listed.
         * 
         * @return builder
         * 
         */
        public Builder loadBalancerId(String loadBalancerId) {
            $.loadBalancerId = loadBalancerId;
            return this;
        }

        public GetCertificatesPlainArgs build() {
            if ($.loadBalancerId == null) {
                throw new MissingRequiredPropertyException("GetCertificatesPlainArgs", "loadBalancerId");
            }
            return $;
        }
    }

}

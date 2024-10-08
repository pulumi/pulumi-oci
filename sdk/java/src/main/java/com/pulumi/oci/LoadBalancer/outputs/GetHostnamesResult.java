// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LoadBalancer.outputs.GetHostnamesFilter;
import com.pulumi.oci.LoadBalancer.outputs.GetHostnamesHostname;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetHostnamesResult {
    private @Nullable List<GetHostnamesFilter> filters;
    /**
     * @return The list of hostnames.
     * 
     */
    private List<GetHostnamesHostname> hostnames;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String loadBalancerId;

    private GetHostnamesResult() {}
    public List<GetHostnamesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The list of hostnames.
     * 
     */
    public List<GetHostnamesHostname> hostnames() {
        return this.hostnames;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String loadBalancerId() {
        return this.loadBalancerId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetHostnamesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetHostnamesFilter> filters;
        private List<GetHostnamesHostname> hostnames;
        private String id;
        private String loadBalancerId;
        public Builder() {}
        public Builder(GetHostnamesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.hostnames = defaults.hostnames;
    	      this.id = defaults.id;
    	      this.loadBalancerId = defaults.loadBalancerId;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetHostnamesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetHostnamesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder hostnames(List<GetHostnamesHostname> hostnames) {
            if (hostnames == null) {
              throw new MissingRequiredPropertyException("GetHostnamesResult", "hostnames");
            }
            this.hostnames = hostnames;
            return this;
        }
        public Builder hostnames(GetHostnamesHostname... hostnames) {
            return hostnames(List.of(hostnames));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetHostnamesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder loadBalancerId(String loadBalancerId) {
            if (loadBalancerId == null) {
              throw new MissingRequiredPropertyException("GetHostnamesResult", "loadBalancerId");
            }
            this.loadBalancerId = loadBalancerId;
            return this;
        }
        public GetHostnamesResult build() {
            final var _resultValue = new GetHostnamesResult();
            _resultValue.filters = filters;
            _resultValue.hostnames = hostnames;
            _resultValue.id = id;
            _resultValue.loadBalancerId = loadBalancerId;
            return _resultValue;
        }
    }
}

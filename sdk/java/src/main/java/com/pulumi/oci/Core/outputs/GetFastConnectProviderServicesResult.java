// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetFastConnectProviderServicesFastConnectProviderService;
import com.pulumi.oci.Core.outputs.GetFastConnectProviderServicesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetFastConnectProviderServicesResult {
    private final String compartmentId;
    /**
     * @return The list of fast_connect_provider_services.
     * 
     */
    private final List<GetFastConnectProviderServicesFastConnectProviderService> fastConnectProviderServices;
    private final @Nullable List<GetFastConnectProviderServicesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;

    @CustomType.Constructor
    private GetFastConnectProviderServicesResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("fastConnectProviderServices") List<GetFastConnectProviderServicesFastConnectProviderService> fastConnectProviderServices,
        @CustomType.Parameter("filters") @Nullable List<GetFastConnectProviderServicesFilter> filters,
        @CustomType.Parameter("id") String id) {
        this.compartmentId = compartmentId;
        this.fastConnectProviderServices = fastConnectProviderServices;
        this.filters = filters;
        this.id = id;
    }

    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of fast_connect_provider_services.
     * 
     */
    public List<GetFastConnectProviderServicesFastConnectProviderService> fastConnectProviderServices() {
        return this.fastConnectProviderServices;
    }
    public List<GetFastConnectProviderServicesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFastConnectProviderServicesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private List<GetFastConnectProviderServicesFastConnectProviderService> fastConnectProviderServices;
        private @Nullable List<GetFastConnectProviderServicesFilter> filters;
        private String id;

        public Builder() {
    	      // Empty
        }

        public Builder(GetFastConnectProviderServicesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.fastConnectProviderServices = defaults.fastConnectProviderServices;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder fastConnectProviderServices(List<GetFastConnectProviderServicesFastConnectProviderService> fastConnectProviderServices) {
            this.fastConnectProviderServices = Objects.requireNonNull(fastConnectProviderServices);
            return this;
        }
        public Builder fastConnectProviderServices(GetFastConnectProviderServicesFastConnectProviderService... fastConnectProviderServices) {
            return fastConnectProviderServices(List.of(fastConnectProviderServices));
        }
        public Builder filters(@Nullable List<GetFastConnectProviderServicesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetFastConnectProviderServicesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }        public GetFastConnectProviderServicesResult build() {
            return new GetFastConnectProviderServicesResult(compartmentId, fastConnectProviderServices, filters, id);
        }
    }
}

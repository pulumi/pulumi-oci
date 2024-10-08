// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetSoftwareUpdate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetSoftwareUpdate.outputs.GetFsuCollectionFleetDiscoveryFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetFsuCollectionFleetDiscovery {
    /**
     * @return Filters to perform the target discovery.
     * 
     */
    private List<GetFsuCollectionFleetDiscoveryFilter> filters;
    /**
     * @return OCIDs of Fleet Software Update Discovery.
     * 
     */
    private String fsuDiscoveryId;
    /**
     * @return Oracle Cloud Infrastructure Search Service query string.
     * 
     */
    private String query;
    /**
     * @return Possible fleet discovery strategies.
     * 
     */
    private String strategy;
    /**
     * @return OCIDs of target resources to include. For EXACC service type Collections only VMClusters are allowed. For EXACS service type Collections only CloudVMClusters are allowed.
     * 
     */
    private List<String> targets;

    private GetFsuCollectionFleetDiscovery() {}
    /**
     * @return Filters to perform the target discovery.
     * 
     */
    public List<GetFsuCollectionFleetDiscoveryFilter> filters() {
        return this.filters;
    }
    /**
     * @return OCIDs of Fleet Software Update Discovery.
     * 
     */
    public String fsuDiscoveryId() {
        return this.fsuDiscoveryId;
    }
    /**
     * @return Oracle Cloud Infrastructure Search Service query string.
     * 
     */
    public String query() {
        return this.query;
    }
    /**
     * @return Possible fleet discovery strategies.
     * 
     */
    public String strategy() {
        return this.strategy;
    }
    /**
     * @return OCIDs of target resources to include. For EXACC service type Collections only VMClusters are allowed. For EXACS service type Collections only CloudVMClusters are allowed.
     * 
     */
    public List<String> targets() {
        return this.targets;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFsuCollectionFleetDiscovery defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetFsuCollectionFleetDiscoveryFilter> filters;
        private String fsuDiscoveryId;
        private String query;
        private String strategy;
        private List<String> targets;
        public Builder() {}
        public Builder(GetFsuCollectionFleetDiscovery defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.fsuDiscoveryId = defaults.fsuDiscoveryId;
    	      this.query = defaults.query;
    	      this.strategy = defaults.strategy;
    	      this.targets = defaults.targets;
        }

        @CustomType.Setter
        public Builder filters(List<GetFsuCollectionFleetDiscoveryFilter> filters) {
            if (filters == null) {
              throw new MissingRequiredPropertyException("GetFsuCollectionFleetDiscovery", "filters");
            }
            this.filters = filters;
            return this;
        }
        public Builder filters(GetFsuCollectionFleetDiscoveryFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder fsuDiscoveryId(String fsuDiscoveryId) {
            if (fsuDiscoveryId == null) {
              throw new MissingRequiredPropertyException("GetFsuCollectionFleetDiscovery", "fsuDiscoveryId");
            }
            this.fsuDiscoveryId = fsuDiscoveryId;
            return this;
        }
        @CustomType.Setter
        public Builder query(String query) {
            if (query == null) {
              throw new MissingRequiredPropertyException("GetFsuCollectionFleetDiscovery", "query");
            }
            this.query = query;
            return this;
        }
        @CustomType.Setter
        public Builder strategy(String strategy) {
            if (strategy == null) {
              throw new MissingRequiredPropertyException("GetFsuCollectionFleetDiscovery", "strategy");
            }
            this.strategy = strategy;
            return this;
        }
        @CustomType.Setter
        public Builder targets(List<String> targets) {
            if (targets == null) {
              throw new MissingRequiredPropertyException("GetFsuCollectionFleetDiscovery", "targets");
            }
            this.targets = targets;
            return this;
        }
        public Builder targets(String... targets) {
            return targets(List.of(targets));
        }
        public GetFsuCollectionFleetDiscovery build() {
            final var _resultValue = new GetFsuCollectionFleetDiscovery();
            _resultValue.filters = filters;
            _resultValue.fsuDiscoveryId = fsuDiscoveryId;
            _resultValue.query = query;
            _resultValue.strategy = strategy;
            _resultValue.targets = targets;
            return _resultValue;
        }
    }
}

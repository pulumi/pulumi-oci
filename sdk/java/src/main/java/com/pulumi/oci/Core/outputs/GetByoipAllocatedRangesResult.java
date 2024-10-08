// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetByoipAllocatedRangesByoipAllocatedRangeCollection;
import com.pulumi.oci.Core.outputs.GetByoipAllocatedRangesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetByoipAllocatedRangesResult {
    /**
     * @return The list of byoip_allocated_range_collection.
     * 
     */
    private List<GetByoipAllocatedRangesByoipAllocatedRangeCollection> byoipAllocatedRangeCollections;
    private String byoipRangeId;
    private @Nullable List<GetByoipAllocatedRangesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetByoipAllocatedRangesResult() {}
    /**
     * @return The list of byoip_allocated_range_collection.
     * 
     */
    public List<GetByoipAllocatedRangesByoipAllocatedRangeCollection> byoipAllocatedRangeCollections() {
        return this.byoipAllocatedRangeCollections;
    }
    public String byoipRangeId() {
        return this.byoipRangeId;
    }
    public List<GetByoipAllocatedRangesFilter> filters() {
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

    public static Builder builder(GetByoipAllocatedRangesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetByoipAllocatedRangesByoipAllocatedRangeCollection> byoipAllocatedRangeCollections;
        private String byoipRangeId;
        private @Nullable List<GetByoipAllocatedRangesFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetByoipAllocatedRangesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.byoipAllocatedRangeCollections = defaults.byoipAllocatedRangeCollections;
    	      this.byoipRangeId = defaults.byoipRangeId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder byoipAllocatedRangeCollections(List<GetByoipAllocatedRangesByoipAllocatedRangeCollection> byoipAllocatedRangeCollections) {
            if (byoipAllocatedRangeCollections == null) {
              throw new MissingRequiredPropertyException("GetByoipAllocatedRangesResult", "byoipAllocatedRangeCollections");
            }
            this.byoipAllocatedRangeCollections = byoipAllocatedRangeCollections;
            return this;
        }
        public Builder byoipAllocatedRangeCollections(GetByoipAllocatedRangesByoipAllocatedRangeCollection... byoipAllocatedRangeCollections) {
            return byoipAllocatedRangeCollections(List.of(byoipAllocatedRangeCollections));
        }
        @CustomType.Setter
        public Builder byoipRangeId(String byoipRangeId) {
            if (byoipRangeId == null) {
              throw new MissingRequiredPropertyException("GetByoipAllocatedRangesResult", "byoipRangeId");
            }
            this.byoipRangeId = byoipRangeId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetByoipAllocatedRangesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetByoipAllocatedRangesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetByoipAllocatedRangesResult", "id");
            }
            this.id = id;
            return this;
        }
        public GetByoipAllocatedRangesResult build() {
            final var _resultValue = new GetByoipAllocatedRangesResult();
            _resultValue.byoipAllocatedRangeCollections = byoipAllocatedRangeCollections;
            _resultValue.byoipRangeId = byoipRangeId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            return _resultValue;
        }
    }
}

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.StackMonitoring.outputs.GetProcessSetsFilter;
import com.pulumi.oci.StackMonitoring.outputs.GetProcessSetsProcessSetCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetProcessSetsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Name of the Process Set.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetProcessSetsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of process_set_collection.
     * 
     */
    private List<GetProcessSetsProcessSetCollection> processSetCollections;

    private GetProcessSetsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Name of the Process Set.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetProcessSetsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of process_set_collection.
     * 
     */
    public List<GetProcessSetsProcessSetCollection> processSetCollections() {
        return this.processSetCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProcessSetsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetProcessSetsFilter> filters;
        private String id;
        private List<GetProcessSetsProcessSetCollection> processSetCollections;
        public Builder() {}
        public Builder(GetProcessSetsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.processSetCollections = defaults.processSetCollections;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetProcessSetsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetProcessSetsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetProcessSetsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetProcessSetsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder processSetCollections(List<GetProcessSetsProcessSetCollection> processSetCollections) {
            if (processSetCollections == null) {
              throw new MissingRequiredPropertyException("GetProcessSetsResult", "processSetCollections");
            }
            this.processSetCollections = processSetCollections;
            return this;
        }
        public Builder processSetCollections(GetProcessSetsProcessSetCollection... processSetCollections) {
            return processSetCollections(List.of(processSetCollections));
        }
        public GetProcessSetsResult build() {
            final var _resultValue = new GetProcessSetsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.processSetCollections = processSetCollections;
            return _resultValue;
        }
    }
}

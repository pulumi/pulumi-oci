// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator {
    /**
     * @return The description of the aggregator.
     * 
     */
    private String description;
    /**
     * @return Used to filter by the identifier of the published object.
     * 
     */
    private String identifier;
    /**
     * @return The key of the object.
     * 
     */
    private String key;
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    private String name;
    /**
     * @return The type of the object in patch.
     * 
     */
    private String type;

    private GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator() {}
    /**
     * @return The description of the aggregator.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Used to filter by the identifier of the published object.
     * 
     */
    public String identifier() {
        return this.identifier;
    }
    /**
     * @return The key of the object.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The type of the object in patch.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String description;
        private String identifier;
        private String key;
        private String name;
        private String type;
        public Builder() {}
        public Builder(GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.identifier = defaults.identifier;
    	      this.key = defaults.key;
    	      this.name = defaults.name;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder identifier(String identifier) {
            if (identifier == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator", "identifier");
            }
            this.identifier = identifier;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator", "type");
            }
            this.type = type;
            return this;
        }
        public GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator build() {
            final var _resultValue = new GetWorkspaceApplicationsApplicationSummaryCollectionItemMetadataAggregator();
            _resultValue.description = description;
            _resultValue.identifier = identifier;
            _resultValue.key = key;
            _resultValue.name = name;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}

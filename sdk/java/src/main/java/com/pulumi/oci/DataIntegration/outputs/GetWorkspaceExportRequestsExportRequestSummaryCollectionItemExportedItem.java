// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem {
    /**
     * @return Aggregator key
     * 
     */
    private String aggregatorKey;
    /**
     * @return Object identifier
     * 
     */
    private String identifier;
    /**
     * @return Export object request key
     * 
     */
    private String key;
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    private String name;
    /**
     * @return Object name path
     * 
     */
    private String namePath;
    /**
     * @return Object type
     * 
     */
    private String objectType;
    /**
     * @return Object version
     * 
     */
    private String objectVersion;
    /**
     * @return time at which this object was last updated.
     * 
     */
    private String timeUpdatedInMillis;

    private GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem() {}
    /**
     * @return Aggregator key
     * 
     */
    public String aggregatorKey() {
        return this.aggregatorKey;
    }
    /**
     * @return Object identifier
     * 
     */
    public String identifier() {
        return this.identifier;
    }
    /**
     * @return Export object request key
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
     * @return Object name path
     * 
     */
    public String namePath() {
        return this.namePath;
    }
    /**
     * @return Object type
     * 
     */
    public String objectType() {
        return this.objectType;
    }
    /**
     * @return Object version
     * 
     */
    public String objectVersion() {
        return this.objectVersion;
    }
    /**
     * @return time at which this object was last updated.
     * 
     */
    public String timeUpdatedInMillis() {
        return this.timeUpdatedInMillis;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String aggregatorKey;
        private String identifier;
        private String key;
        private String name;
        private String namePath;
        private String objectType;
        private String objectVersion;
        private String timeUpdatedInMillis;
        public Builder() {}
        public Builder(GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.aggregatorKey = defaults.aggregatorKey;
    	      this.identifier = defaults.identifier;
    	      this.key = defaults.key;
    	      this.name = defaults.name;
    	      this.namePath = defaults.namePath;
    	      this.objectType = defaults.objectType;
    	      this.objectVersion = defaults.objectVersion;
    	      this.timeUpdatedInMillis = defaults.timeUpdatedInMillis;
        }

        @CustomType.Setter
        public Builder aggregatorKey(String aggregatorKey) {
            if (aggregatorKey == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem", "aggregatorKey");
            }
            this.aggregatorKey = aggregatorKey;
            return this;
        }
        @CustomType.Setter
        public Builder identifier(String identifier) {
            if (identifier == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem", "identifier");
            }
            this.identifier = identifier;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder namePath(String namePath) {
            if (namePath == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem", "namePath");
            }
            this.namePath = namePath;
            return this;
        }
        @CustomType.Setter
        public Builder objectType(String objectType) {
            if (objectType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem", "objectType");
            }
            this.objectType = objectType;
            return this;
        }
        @CustomType.Setter
        public Builder objectVersion(String objectVersion) {
            if (objectVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem", "objectVersion");
            }
            this.objectVersion = objectVersion;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdatedInMillis(String timeUpdatedInMillis) {
            if (timeUpdatedInMillis == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem", "timeUpdatedInMillis");
            }
            this.timeUpdatedInMillis = timeUpdatedInMillis;
            return this;
        }
        public GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem build() {
            final var _resultValue = new GetWorkspaceExportRequestsExportRequestSummaryCollectionItemExportedItem();
            _resultValue.aggregatorKey = aggregatorKey;
            _resultValue.identifier = identifier;
            _resultValue.key = key;
            _resultValue.name = name;
            _resultValue.namePath = namePath;
            _resultValue.objectType = objectType;
            _resultValue.objectVersion = objectVersion;
            _resultValue.timeUpdatedInMillis = timeUpdatedInMillis;
            return _resultValue;
        }
    }
}

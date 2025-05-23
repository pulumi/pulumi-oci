// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject {
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
     * @return New key of the object
     * 
     */
    private String newKey;
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
     * @return Old key of the object
     * 
     */
    private String oldKey;
    /**
     * @return Object resolution action
     * 
     */
    private String resolutionAction;
    /**
     * @return time at which this object was last updated.
     * 
     */
    private String timeUpdatedInMillis;

    private GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject() {}
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
     * @return New key of the object
     * 
     */
    public String newKey() {
        return this.newKey;
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
     * @return Old key of the object
     * 
     */
    public String oldKey() {
        return this.oldKey;
    }
    /**
     * @return Object resolution action
     * 
     */
    public String resolutionAction() {
        return this.resolutionAction;
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

    public static Builder builder(GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String aggregatorKey;
        private String identifier;
        private String name;
        private String namePath;
        private String newKey;
        private String objectType;
        private String objectVersion;
        private String oldKey;
        private String resolutionAction;
        private String timeUpdatedInMillis;
        public Builder() {}
        public Builder(GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.aggregatorKey = defaults.aggregatorKey;
    	      this.identifier = defaults.identifier;
    	      this.name = defaults.name;
    	      this.namePath = defaults.namePath;
    	      this.newKey = defaults.newKey;
    	      this.objectType = defaults.objectType;
    	      this.objectVersion = defaults.objectVersion;
    	      this.oldKey = defaults.oldKey;
    	      this.resolutionAction = defaults.resolutionAction;
    	      this.timeUpdatedInMillis = defaults.timeUpdatedInMillis;
        }

        @CustomType.Setter
        public Builder aggregatorKey(String aggregatorKey) {
            if (aggregatorKey == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject", "aggregatorKey");
            }
            this.aggregatorKey = aggregatorKey;
            return this;
        }
        @CustomType.Setter
        public Builder identifier(String identifier) {
            if (identifier == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject", "identifier");
            }
            this.identifier = identifier;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder namePath(String namePath) {
            if (namePath == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject", "namePath");
            }
            this.namePath = namePath;
            return this;
        }
        @CustomType.Setter
        public Builder newKey(String newKey) {
            if (newKey == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject", "newKey");
            }
            this.newKey = newKey;
            return this;
        }
        @CustomType.Setter
        public Builder objectType(String objectType) {
            if (objectType == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject", "objectType");
            }
            this.objectType = objectType;
            return this;
        }
        @CustomType.Setter
        public Builder objectVersion(String objectVersion) {
            if (objectVersion == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject", "objectVersion");
            }
            this.objectVersion = objectVersion;
            return this;
        }
        @CustomType.Setter
        public Builder oldKey(String oldKey) {
            if (oldKey == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject", "oldKey");
            }
            this.oldKey = oldKey;
            return this;
        }
        @CustomType.Setter
        public Builder resolutionAction(String resolutionAction) {
            if (resolutionAction == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject", "resolutionAction");
            }
            this.resolutionAction = resolutionAction;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdatedInMillis(String timeUpdatedInMillis) {
            if (timeUpdatedInMillis == null) {
              throw new MissingRequiredPropertyException("GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject", "timeUpdatedInMillis");
            }
            this.timeUpdatedInMillis = timeUpdatedInMillis;
            return this;
        }
        public GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject build() {
            final var _resultValue = new GetWorkspaceImportRequestsImportRequestSummaryCollectionItemImportedObject();
            _resultValue.aggregatorKey = aggregatorKey;
            _resultValue.identifier = identifier;
            _resultValue.name = name;
            _resultValue.namePath = namePath;
            _resultValue.newKey = newKey;
            _resultValue.objectType = objectType;
            _resultValue.objectVersion = objectVersion;
            _resultValue.oldKey = oldKey;
            _resultValue.resolutionAction = resolutionAction;
            _resultValue.timeUpdatedInMillis = timeUpdatedInMillis;
            return _resultValue;
        }
    }
}

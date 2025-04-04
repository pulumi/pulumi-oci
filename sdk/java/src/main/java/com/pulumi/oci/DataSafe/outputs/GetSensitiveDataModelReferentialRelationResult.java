// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetSensitiveDataModelReferentialRelationChild;
import com.pulumi.oci.DataSafe.outputs.GetSensitiveDataModelReferentialRelationParent;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSensitiveDataModelReferentialRelationResult {
    /**
     * @return columnsInfo object has details of column group with schema details.
     * 
     */
    private List<GetSensitiveDataModelReferentialRelationChild> children;
    private String id;
    /**
     * @return Determines if the columns present in the referential relation is present in the sensitive data model
     * 
     */
    private Boolean isSensitive;
    /**
     * @return The unique key that identifies the referential relation. It&#39;s numeric and unique within a sensitive data model.
     * 
     */
    private String key;
    /**
     * @return columnsInfo object has details of column group with schema details.
     * 
     */
    private List<GetSensitiveDataModelReferentialRelationParent> parents;
    /**
     * @return The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
     * 
     */
    private String relationType;
    /**
     * @return The OCID of the sensitive data model that contains the sensitive column.
     * 
     */
    private String sensitiveDataModelId;
    /**
     * @return The current state of the referential relation.
     * 
     */
    private String state;

    private GetSensitiveDataModelReferentialRelationResult() {}
    /**
     * @return columnsInfo object has details of column group with schema details.
     * 
     */
    public List<GetSensitiveDataModelReferentialRelationChild> children() {
        return this.children;
    }
    public String id() {
        return this.id;
    }
    /**
     * @return Determines if the columns present in the referential relation is present in the sensitive data model
     * 
     */
    public Boolean isSensitive() {
        return this.isSensitive;
    }
    /**
     * @return The unique key that identifies the referential relation. It&#39;s numeric and unique within a sensitive data model.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return columnsInfo object has details of column group with schema details.
     * 
     */
    public List<GetSensitiveDataModelReferentialRelationParent> parents() {
        return this.parents;
    }
    /**
     * @return The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
     * 
     */
    public String relationType() {
        return this.relationType;
    }
    /**
     * @return The OCID of the sensitive data model that contains the sensitive column.
     * 
     */
    public String sensitiveDataModelId() {
        return this.sensitiveDataModelId;
    }
    /**
     * @return The current state of the referential relation.
     * 
     */
    public String state() {
        return this.state;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSensitiveDataModelReferentialRelationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSensitiveDataModelReferentialRelationChild> children;
        private String id;
        private Boolean isSensitive;
        private String key;
        private List<GetSensitiveDataModelReferentialRelationParent> parents;
        private String relationType;
        private String sensitiveDataModelId;
        private String state;
        public Builder() {}
        public Builder(GetSensitiveDataModelReferentialRelationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.children = defaults.children;
    	      this.id = defaults.id;
    	      this.isSensitive = defaults.isSensitive;
    	      this.key = defaults.key;
    	      this.parents = defaults.parents;
    	      this.relationType = defaults.relationType;
    	      this.sensitiveDataModelId = defaults.sensitiveDataModelId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder children(List<GetSensitiveDataModelReferentialRelationChild> children) {
            if (children == null) {
              throw new MissingRequiredPropertyException("GetSensitiveDataModelReferentialRelationResult", "children");
            }
            this.children = children;
            return this;
        }
        public Builder children(GetSensitiveDataModelReferentialRelationChild... children) {
            return children(List.of(children));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSensitiveDataModelReferentialRelationResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isSensitive(Boolean isSensitive) {
            if (isSensitive == null) {
              throw new MissingRequiredPropertyException("GetSensitiveDataModelReferentialRelationResult", "isSensitive");
            }
            this.isSensitive = isSensitive;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetSensitiveDataModelReferentialRelationResult", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder parents(List<GetSensitiveDataModelReferentialRelationParent> parents) {
            if (parents == null) {
              throw new MissingRequiredPropertyException("GetSensitiveDataModelReferentialRelationResult", "parents");
            }
            this.parents = parents;
            return this;
        }
        public Builder parents(GetSensitiveDataModelReferentialRelationParent... parents) {
            return parents(List.of(parents));
        }
        @CustomType.Setter
        public Builder relationType(String relationType) {
            if (relationType == null) {
              throw new MissingRequiredPropertyException("GetSensitiveDataModelReferentialRelationResult", "relationType");
            }
            this.relationType = relationType;
            return this;
        }
        @CustomType.Setter
        public Builder sensitiveDataModelId(String sensitiveDataModelId) {
            if (sensitiveDataModelId == null) {
              throw new MissingRequiredPropertyException("GetSensitiveDataModelReferentialRelationResult", "sensitiveDataModelId");
            }
            this.sensitiveDataModelId = sensitiveDataModelId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetSensitiveDataModelReferentialRelationResult", "state");
            }
            this.state = state;
            return this;
        }
        public GetSensitiveDataModelReferentialRelationResult build() {
            final var _resultValue = new GetSensitiveDataModelReferentialRelationResult();
            _resultValue.children = children;
            _resultValue.id = id;
            _resultValue.isSensitive = isSensitive;
            _resultValue.key = key;
            _resultValue.parents = parents;
            _resultValue.relationType = relationType;
            _resultValue.sensitiveDataModelId = sensitiveDataModelId;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}

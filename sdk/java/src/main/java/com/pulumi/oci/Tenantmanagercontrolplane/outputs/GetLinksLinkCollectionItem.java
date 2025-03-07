// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetLinksLinkCollectionItem {
    /**
     * @return The ID of the child tenancy this link is associated with.
     * 
     */
    private String childTenancyId;
    /**
     * @return OCID of the link.
     * 
     */
    private String id;
    /**
     * @return The ID of the parent tenancy this link is associated with.
     * 
     */
    private String parentTenancyId;
    /**
     * @return The lifecycle state of the resource.
     * 
     */
    private String state;
    /**
     * @return Date-time when this link was created.
     * 
     */
    private String timeCreated;
    /**
     * @return Date-time when this link was terminated.
     * 
     */
    private String timeTerminated;
    /**
     * @return Date-time when this link was last updated.
     * 
     */
    private String timeUpdated;

    private GetLinksLinkCollectionItem() {}
    /**
     * @return The ID of the child tenancy this link is associated with.
     * 
     */
    public String childTenancyId() {
        return this.childTenancyId;
    }
    /**
     * @return OCID of the link.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The ID of the parent tenancy this link is associated with.
     * 
     */
    public String parentTenancyId() {
        return this.parentTenancyId;
    }
    /**
     * @return The lifecycle state of the resource.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Date-time when this link was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Date-time when this link was terminated.
     * 
     */
    public String timeTerminated() {
        return this.timeTerminated;
    }
    /**
     * @return Date-time when this link was last updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLinksLinkCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String childTenancyId;
        private String id;
        private String parentTenancyId;
        private String state;
        private String timeCreated;
        private String timeTerminated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetLinksLinkCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.childTenancyId = defaults.childTenancyId;
    	      this.id = defaults.id;
    	      this.parentTenancyId = defaults.parentTenancyId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeTerminated = defaults.timeTerminated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder childTenancyId(String childTenancyId) {
            if (childTenancyId == null) {
              throw new MissingRequiredPropertyException("GetLinksLinkCollectionItem", "childTenancyId");
            }
            this.childTenancyId = childTenancyId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetLinksLinkCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder parentTenancyId(String parentTenancyId) {
            if (parentTenancyId == null) {
              throw new MissingRequiredPropertyException("GetLinksLinkCollectionItem", "parentTenancyId");
            }
            this.parentTenancyId = parentTenancyId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetLinksLinkCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetLinksLinkCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeTerminated(String timeTerminated) {
            if (timeTerminated == null) {
              throw new MissingRequiredPropertyException("GetLinksLinkCollectionItem", "timeTerminated");
            }
            this.timeTerminated = timeTerminated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetLinksLinkCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetLinksLinkCollectionItem build() {
            final var _resultValue = new GetLinksLinkCollectionItem();
            _resultValue.childTenancyId = childTenancyId;
            _resultValue.id = id;
            _resultValue.parentTenancyId = parentTenancyId;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeTerminated = timeTerminated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}

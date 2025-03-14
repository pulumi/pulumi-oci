// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup {
    /**
     * @return (Updatable) Flag controlling whether group membership can be request by user through self service console.
     * 
     * **Added In:** 17.3.4
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Requestable, mapsTo:requestable]]
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: boolean
     * * uniqueness: none
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private @Nullable Boolean requestable;

    private DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup() {}
    /**
     * @return (Updatable) Flag controlling whether group membership can be request by user through self service console.
     * 
     * **Added In:** 17.3.4
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Requestable, mapsTo:requestable]]
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: boolean
     * * uniqueness: none
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Boolean> requestable() {
        return Optional.ofNullable(this.requestable);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean requestable;
        public Builder() {}
        public Builder(DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.requestable = defaults.requestable;
        }

        @CustomType.Setter
        public Builder requestable(@Nullable Boolean requestable) {

            this.requestable = requestable;
            return this;
        }
        public DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup build() {
            final var _resultValue = new DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup();
            _resultValue.requestable = requestable;
            return _resultValue;
        }
    }
}

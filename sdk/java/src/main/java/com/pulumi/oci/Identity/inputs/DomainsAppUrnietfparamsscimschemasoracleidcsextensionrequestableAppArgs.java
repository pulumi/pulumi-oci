// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs Empty = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs();

    /**
     * (Updatable) Flag controlling whether resource can be request by user through self service console.
     * 
     * **Added In:** 17.3.4
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Import(name="requestable")
    private @Nullable Output<Boolean> requestable;

    /**
     * @return (Updatable) Flag controlling whether resource can be request by user through self service console.
     * 
     * **Added In:** 17.3.4
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Optional<Output<Boolean>> requestable() {
        return Optional.ofNullable(this.requestable);
    }

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs() {}

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs(DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs $) {
        this.requestable = $.requestable;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs $;

        public Builder() {
            $ = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs();
        }

        public Builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs defaults) {
            $ = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param requestable (Updatable) Flag controlling whether resource can be request by user through self service console.
         * 
         * **Added In:** 17.3.4
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: request
         * * type: boolean
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder requestable(@Nullable Output<Boolean> requestable) {
            $.requestable = requestable;
            return this;
        }

        /**
         * @param requestable (Updatable) Flag controlling whether resource can be request by user through self service console.
         * 
         * **Added In:** 17.3.4
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: request
         * * type: boolean
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder requestable(Boolean requestable) {
            return requestable(Output.of(requestable));
        }

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableAppArgs build() {
            return $;
        }
    }

}
// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs Empty = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs();

    /**
     * (Updatable) Display-name of the AppRole.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="display")
    private @Nullable Output<String> display;

    /**
     * @return (Updatable) Display-name of the AppRole.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> display() {
        return Optional.ofNullable(this.display);
    }

    /**
     * (Updatable) If true, the object class represents an account. The isAccountObjectClass attribute value &#39;true&#39; MUST appear no more than once.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Import(name="isAccountObjectClass")
    private @Nullable Output<Boolean> isAccountObjectClass;

    /**
     * @return (Updatable) If true, the object class represents an account. The isAccountObjectClass attribute value &#39;true&#39; MUST appear no more than once.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Optional<Output<Boolean>> isAccountObjectClass() {
        return Optional.ofNullable(this.isAccountObjectClass);
    }

    /**
     * (Updatable) URI of the AppRole.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    @Import(name="ref")
    private @Nullable Output<String> ref;

    /**
     * @return (Updatable) URI of the AppRole.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> ref() {
        return Optional.ofNullable(this.ref);
    }

    /**
     * (Updatable) Object class resource type
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="resourceType")
    private @Nullable Output<String> resourceType;

    /**
     * @return (Updatable) Object class resource type
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }

    /**
     * (Updatable) Object Class type. Allowed values are AccountObjectClass, ManagedObjectClass.
     * 
     * **Added In:** 18.1.6
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsDefaultValue: AccountObjectClass
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) Object Class type. Allowed values are AccountObjectClass, ManagedObjectClass.
     * 
     * **Added In:** 18.1.6
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsDefaultValue: AccountObjectClass
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * (Updatable) ID of the AppRole.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return (Updatable) ID of the AppRole.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs() {}

    private DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs(DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs $) {
        this.display = $.display;
        this.isAccountObjectClass = $.isAccountObjectClass;
        this.ref = $.ref;
        this.resourceType = $.resourceType;
        this.type = $.type;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs $;

        public Builder() {
            $ = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs();
        }

        public Builder(DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs defaults) {
            $ = new DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param display (Updatable) Display-name of the AppRole.
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(@Nullable Output<String> display) {
            $.display = display;
            return this;
        }

        /**
         * @param display (Updatable) Display-name of the AppRole.
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(String display) {
            return display(Output.of(display));
        }

        /**
         * @param isAccountObjectClass (Updatable) If true, the object class represents an account. The isAccountObjectClass attribute value &#39;true&#39; MUST appear no more than once.
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: default
         * * type: boolean
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder isAccountObjectClass(@Nullable Output<Boolean> isAccountObjectClass) {
            $.isAccountObjectClass = isAccountObjectClass;
            return this;
        }

        /**
         * @param isAccountObjectClass (Updatable) If true, the object class represents an account. The isAccountObjectClass attribute value &#39;true&#39; MUST appear no more than once.
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: default
         * * type: boolean
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder isAccountObjectClass(Boolean isAccountObjectClass) {
            return isAccountObjectClass(Output.of(isAccountObjectClass));
        }

        /**
         * @param ref (Updatable) URI of the AppRole.
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: reference
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ref(@Nullable Output<String> ref) {
            $.ref = ref;
            return this;
        }

        /**
         * @param ref (Updatable) URI of the AppRole.
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: reference
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ref(String ref) {
            return ref(Output.of(ref));
        }

        /**
         * @param resourceType (Updatable) Object class resource type
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder resourceType(@Nullable Output<String> resourceType) {
            $.resourceType = resourceType;
            return this;
        }

        /**
         * @param resourceType (Updatable) Object class resource type
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder resourceType(String resourceType) {
            return resourceType(Output.of(resourceType));
        }

        /**
         * @param type (Updatable) Object Class type. Allowed values are AccountObjectClass, ManagedObjectClass.
         * 
         * **Added In:** 18.1.6
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsDefaultValue: AccountObjectClass
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) Object Class type. Allowed values are AccountObjectClass, ManagedObjectClass.
         * 
         * **Added In:** 18.1.6
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsDefaultValue: AccountObjectClass
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param value (Updatable) ID of the AppRole.
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) ID of the AppRole.
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppObjectClassArgs build() {
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            $.value = Objects.requireNonNull($.value, "expected parameter 'value' to be non-null");
            return $;
        }
    }

}
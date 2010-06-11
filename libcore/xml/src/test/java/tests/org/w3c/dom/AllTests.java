/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tests.org.w3c.dom;

import junit.framework.Test;
import junit.framework.TestSuite;

/**
 * This is autogenerated source file. Includes tests for package org.w3c.dom;
 */

public class AllTests {

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AllTests.suite());
    }

    public static Test suite() {
        TestSuite suite = tests.TestSuiteFactory.createTestSuite("All tests for package org.w3c.dom;");
        // $JUnit-BEGIN$

        suite.addTestSuite(AttrGetOwnerElement.class);
        suite.addTestSuite(CreateAttributeNS.class);
        suite.addTestSuite(CreateDocument.class);
        suite.addTestSuite(CreateDocumentType.class);
        suite.addTestSuite(CreateElementNS.class);
        suite.addTestSuite(DOMImplementationCreateDocument.class);
        suite.addTestSuite(DOMImplementationCreateDocumentType.class);
        suite.addTestSuite(DOMImplementationHasFeature.class);
        suite.addTestSuite(DocumentCreateAttributeNS.class);
        suite.addTestSuite(DocumentCreateElementNS.class);
        suite.addTestSuite(DocumentGetElementsByTagnameNS.class);
        suite.addTestSuite(DocumentGeteEementById.class);
        suite.addTestSuite(DocumentImportNode.class);
        suite.addTestSuite(DocumentTypeInternalSubset.class);
        suite.addTestSuite(DocumentTypePublicId.class);
        suite.addTestSuite(DocumentTypeSystemId.class);
// Is empty. Only test assumes validation. Leave disabled.        
//        suite.addTestSuite(ElementGetAttributeNS.class);
        suite.addTestSuite(ElementGetAttributeNodeNS.class);
        suite.addTestSuite(ElementGetElementsByTagNameNS.class);
        suite.addTestSuite(ElementHasAttribute.class);
        suite.addTestSuite(ElementHasAttributeNS.class);
        suite.addTestSuite(ElementRemoveAttributeNS.class);
        suite.addTestSuite(ElementSetAttributeNS.class);
        suite.addTestSuite(ElementSetAttributeNodeNS.class);
        suite.addTestSuite(GetAttributeNS.class);
        suite.addTestSuite(GetAttributeNodeNS.class);
        suite.addTestSuite(GetElementById.class);
        suite.addTestSuite(GetElementsByTagNameNS.class);
        suite.addTestSuite(GetNamedItemNS.class);
// Is empty. Only test assumes validation. Leave disabled.        
//        suite.addTestSuite(HCEntitiesRemoveNamedItemNS.class);
// Is empty. Only test assumes validation. Leave disabled.        
//        suite.addTestSuite(HCEntitiesSetNamedItemNS.class);
        suite.addTestSuite(HCNamedNodeMapInvalidType.class);
        suite.addTestSuite(HCNodeDocumentFragmentNormalize.class);
// Is empty. Only test assumes validation. Leave disabled.        
//        suite.addTestSuite(HCNotationsRemoveNamedItemNS.class);
// Is empty. Only test assumes validation. Leave disabled.        
//        suite.addTestSuite(HCNotationsSetNamedItemNS.class);
        suite.addTestSuite(HasAttribute.class);
        suite.addTestSuite(HasAttributeNS.class);
        suite.addTestSuite(HasAttributes.class);
        suite.addTestSuite(ImportNode.class);
        suite.addTestSuite(InternalSubset.class);
        suite.addTestSuite(IsSupported.class);
        suite.addTestSuite(LocalName.class);
        suite.addTestSuite(NamedNodeMapGetNamedItemNS.class);
        suite.addTestSuite(NamedNodeMapRemoveNamedItemNS.class);
        suite.addTestSuite(NamedNodeMapSetNamedItemNS.class);
        suite.addTestSuite(NamespaceURI.class);
        suite.addTestSuite(NodeGetLocalName.class);
        suite.addTestSuite(NodeGetNamespaceURI.class);
        suite.addTestSuite(NodeGetOwnerDocument.class);
        suite.addTestSuite(NodeGetPrefix.class);
        suite.addTestSuite(NodeHasAttributes.class);
        suite.addTestSuite(NodeIsSupported.class);
        suite.addTestSuite(NodeNormalize.class);
        suite.addTestSuite(NodeSetPrefix.class);
        suite.addTestSuite(Normalize.class);
        suite.addTestSuite(OwnerDocument.class);
        suite.addTestSuite(OwnerElement.class);
        suite.addTestSuite(Prefix.class);
        suite.addTestSuite(PublicId.class);
// Is empty. Only test assumes validation. Leave disabled.        
//        suite.addTestSuite(RemoveAttributeNS.class);
        suite.addTestSuite(RemoveNamedItemNS.class);
        suite.addTestSuite(SetAttributeNS.class);
        suite.addTestSuite(SetAttributeNodeNS.class);
        suite.addTestSuite(SetNamedItemNS.class);
        suite.addTestSuite(SystemId.class);
        // $JUnit-END$
        return suite;
    }
}
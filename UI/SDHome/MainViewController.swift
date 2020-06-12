//
//  ViewController.swift
//  SDHome
//
//  Created by Mike Zhao on 2/28/20.
//  Copyright © 2020 SCU. All rights reserved.
//

import UIKit

class MainViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        print("SD Home page has loaded")
    }

    @IBAction func manageWebsiteBox(_ sender: UIButton) {
        print("Manage Website pressed")
        
        //self.performSegue(withIdentifier: "WebsiteSegue", sender:self)
    }
    
    @IBAction func networkMonitorBox(_ sender: UIButton) {
        print("Network Monitor pressed")
        self.performSegue(withIdentifier:"NetworkSegue", sender:self)
    }
    
    @IBAction func flowBox(_ sender: UIButton) {
        print("Flow pressed")
        self.performSegue(withIdentifier: "FlowSegue", sender:self)
    }
}


